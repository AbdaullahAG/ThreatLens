"""Unit tests for the Splunk, Elastic, and Sentinel exporters (mocked HTTP)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch


from src.exporters.base import BaseExporter, ExportResult
from src.exporters.dispatcher import build_exporters, export_results
from src.exporters.elastic import ElasticExporter
from src.exporters.sentinel import SentinelExporter
from src.exporters.splunk import SplunkExporter
from src.utils.config import Config


def _ok_response(body: dict | None = None, status: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = body or {}
    return resp


class TestSplunkExporter:
    def test_send_batch_success(self):
        exporter = SplunkExporter(hec_url="https://splunk.internal:8088", hec_token="secret-token")
        with patch.object(exporter.session, "post", return_value=_ok_response()) as mock_post:
            result = exporter.send_batch([{"ioc": "8.8.8.8"}])
        assert result.success is True
        assert result.sent == 1
        call_kwargs = mock_post.call_args.kwargs
        assert call_kwargs["headers"]["Authorization"] == "Splunk secret-token"
        assert call_kwargs["verify"] is True

    def test_wrong_host_is_blocked_no_http_call(self):
        exporter = SplunkExporter(hec_url="https://splunk.internal:8088", hec_token="x")
        exporter.hec_url = "https://evil.example.com"  # simulate a tampered destination
        with patch.object(exporter.session, "post") as mock_post:
            result = exporter.send_batch([{"a": 1}])
        mock_post.assert_not_called()
        assert result.success is False

    def test_token_never_appears_in_error_logs(self, caplog):
        exporter = SplunkExporter(hec_url="https://splunk.internal:8088", hec_token="SUPER-SECRET-TOKEN")
        import requests
        with patch.object(exporter.session, "post", side_effect=requests.exceptions.ConnectionError("SUPER-SECRET-TOKEN leaked in url")):
            with caplog.at_level("WARNING"):
                exporter.send_batch([{"a": 1}])
        assert "SUPER-SECRET-TOKEN" not in caplog.text

    def test_insecure_tls_logs_warning(self, caplog):
        with caplog.at_level("WARNING"):
            SplunkExporter(hec_url="https://splunk.internal:8088", hec_token="x", verify_tls=False)
        assert "DISABLED" in caplog.text

    def test_batching_respects_batch_size(self):
        exporter = SplunkExporter(hec_url="https://splunk.internal:8088", hec_token="x", batch_size=2)
        with patch.object(exporter.session, "post", return_value=_ok_response()) as mock_post:
            exporter.send_batch([{"i": i} for i in range(5)])
        assert mock_post.call_count == 3  # 2 + 2 + 1


class TestElasticExporter:
    def test_send_batch_uses_bulk_ndjson(self):
        exporter = ElasticExporter(elastic_url="https://es.internal:9200", api_key="key123")
        with patch.object(exporter.session, "post", return_value=_ok_response()) as mock_post:
            result = exporter.send_batch([{"ioc": "8.8.8.8"}])
        assert result.success is True
        call_kwargs = mock_post.call_args.kwargs
        assert call_kwargs["headers"]["Authorization"] == "ApiKey key123"
        assert call_kwargs["headers"]["Content-Type"] == "application/x-ndjson"
        assert "\n" in call_kwargs["data"]

    def test_server_error_retries_then_fails(self):
        exporter = ElasticExporter(elastic_url="https://es.internal:9200", api_key="key123", max_retries=1, backoff_seconds=0)
        with patch.object(exporter.session, "post", return_value=_ok_response(status=503)) as mock_post:
            result = exporter.send_batch([{"a": 1}])
        assert mock_post.call_count == 2  # 1 initial + 1 retry
        assert result.success is False


class TestSentinelExporter:
    def _exporter(self, **overrides):
        defaults = dict(
            tenant_id="tenant-1",
            client_id="client-1",
            client_secret="super-secret",
            dce_endpoint="https://my-dce.eastus-1.ingest.monitor.azure.com",
            dcr_immutable_id="dcr-123",
            stream_name="Custom-ThreatLens",
        )
        defaults.update(overrides)
        return SentinelExporter(**defaults)

    def test_uses_logs_ingestion_api_not_legacy(self):
        exporter = self._exporter()
        token_resp = _ok_response({"access_token": "abc-token", "expires_in": 3600})
        with patch.object(exporter.session, "post", side_effect=[token_resp, _ok_response()]) as mock_post:
            result = exporter.send_batch([{"ioc": "8.8.8.8"}])
        assert result.success is True
        urls_called = [call.args[0] for call in mock_post.call_args_list]
        assert "login.microsoftonline.com" in urls_called[0]
        assert "dataCollectionRules/dcr-123/streams/Custom-ThreatLens" in urls_called[1]
        assert "collector.azure.com" not in " ".join(urls_called)  # not the legacy endpoint

    def test_token_is_cached_across_batches(self):
        exporter = self._exporter()
        token_resp = _ok_response({"access_token": "abc-token", "expires_in": 3600})
        with patch.object(exporter.session, "post", side_effect=[token_resp, _ok_response(), _ok_response()]) as mock_post:
            exporter.send_batch([{"a": 1}])
            exporter.send_batch([{"b": 2}])
        # Only one token request across two send_batch calls.
        token_calls = [c for c in mock_post.call_args_list if "oauth2" in c.args[0]]
        assert len(token_calls) == 1

    def test_auth_failure_does_not_call_ingestion_endpoint(self):
        exporter = self._exporter()
        with patch.object(exporter.session, "post", return_value=_ok_response(status=401)) as mock_post:
            result = exporter.send_batch([{"a": 1}])
        assert result.success is False
        assert mock_post.call_count == 1  # only the (failed) token call


class TestDispatcher:
    def test_only_fully_configured_exporters_are_built(self, tmp_path):
        env_path = tmp_path / "keys.env"
        env_path.write_text("SPLUNK_HEC_URL=https://splunk.internal:8088\nSPLUNK_HEC_TOKEN=tok\n")
        config = Config(config_path=str(env_path))
        exporters = build_exporters(config)
        names = {e.name for e in exporters}
        assert names == {"splunk"}

    def test_no_config_builds_no_exporters(self, tmp_path):
        config = Config(config_path=str(tmp_path / "missing.env"))
        assert build_exporters(config) == []

    def test_one_exporter_failure_does_not_block_others(self):
        good = MagicMock(spec=BaseExporter)
        good.name = "good"
        good.send_batch.return_value = ExportResult(exporter="good", success=True, sent=1)

        bad = MagicMock(spec=BaseExporter)
        bad.name = "bad"
        bad.send_batch.side_effect = RuntimeError("boom")

        from src.models import IOC, IOCType, EnrichmentResult
        results = [EnrichmentResult(ioc=IOC("8.8.8.8", IOCType.IP))]

        outcomes = export_results([good, bad], results)
        assert len(outcomes) == 2
        assert outcomes[0].success is True
        assert outcomes[1].success is False
        assert "boom" in outcomes[1].error
