"""Security-focused tests for the v2.3 privacy and response-validation controls."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from src.enrichers.base import BaseEnricher
from src.models import EnrichmentResult, IOC, IOCType
from src.utils.security import (
    IOCValidationError,
    bounded_json_response,
    sanitize_ioc_for_external,
    sanitize_result_for_output,
    sanitize_sensitive_data,
    validate_https_endpoint,
    validate_ioc,
)


class _Enricher(BaseEnricher):
    name = "test"
    supports = [IOCType.IP]
    allowed_hosts = {"api.example.com"}

    def enrich(self, ioc: IOC, result: EnrichmentResult) -> EnrichmentResult:
        return result


class _Response:
    def __init__(self, chunks: list[bytes], *, content_length: str | None = None):
        self.headers = {"Content-Type": "application/json"}
        if content_length is not None:
            self.headers["Content-Length"] = content_length
        self.chunks = chunks
        self.closed = False

    def iter_content(self, chunk_size: int):
        yield from self.chunks

    def close(self):
        self.closed = True


def test_url_validation_rejects_non_iocs_and_canonicalizes_values():
    assert validate_ioc("EXAMPLE.COM.", IOCType.DOMAIN) == "example.com"
    assert validate_ioc("CVE-2021-44228", IOCType.CVE) == "CVE-2021-44228"
    for candidate in ("127.0.0.1", "https://user:pass@example.com", "not a hash"):
        try:
            validate_ioc(candidate, IOCType.IP if candidate == "127.0.0.1" else IOCType.URL)
        except IOCValidationError:
            pass
        else:
            raise AssertionError(f"Rejected input was accepted: {candidate}")


def test_sensitive_url_query_parameters_are_removed_only_for_external_copy():
    original = IOC(
        "https://example.com/a?keep=yes&access_token=secret&client-secret=x#fragment",
        IOCType.URL,
    )
    external = sanitize_ioc_for_external(original)
    assert original.value.endswith("#fragment")
    assert external.value == "https://example.com/a?keep=yes"


def test_endpoint_validation_requires_exact_host_authority_and_safe_url_shape():
    allow = {"api.example.com"}
    assert validate_https_endpoint("https://api.example.com/v1", allow)
    assert not validate_https_endpoint("http://api.example.com/v1", allow)
    assert not validate_https_endpoint("https://api.example.com.evil.test/v1", allow)
    assert not validate_https_endpoint("https://user@api.example.com/v1", allow)
    assert not validate_https_endpoint("https://api.example.com/v1?token=secret", allow)
    assert not validate_https_endpoint("https://api.example.com:8443/v1", allow)
    assert validate_https_endpoint(
        "https://siem.internal:8088/ingest", {"siem.internal"},
        allowed_authorities={("siem.internal", 8088)},
    )


def test_bounded_json_response_checks_header_and_streamed_bytes_and_closes():
    declared_too_large = _Response([b"{}"], content_length="1000")
    assert bounded_json_response(declared_too_large, max_bytes=8) is None
    assert declared_too_large.closed

    streamed_too_large = _Response([b'{"x":', b'"123456789"}'])
    assert bounded_json_response(streamed_too_large, max_bytes=8) is None
    assert streamed_too_large.closed

    valid = _Response([b'{"data":', b'[]}'])
    assert bounded_json_response(valid, max_bytes=32) == {"data": []}
    assert valid.closed


def test_provider_get_uses_tls_redirect_blocking_and_bounded_streaming():
    enricher = _Enricher(api_key="secret", delay=0)
    response = MagicMock()
    response.status_code = 200
    response.headers = {"Content-Type": "application/json", "Content-Length": "2"}
    response.iter_content.return_value = [b"[]"]
    with patch.object(enricher.session, "get", return_value=response) as mock_get:
        assert enricher.get("https://api.example.com/v1") is None
    kwargs = mock_get.call_args.kwargs
    assert kwargs["allow_redirects"] is False
    assert kwargs["verify"] is True
    assert kwargs["stream"] is True
    response.close.assert_called_once()


def test_output_clone_redacts_configured_secrets_and_url_credentials():
    result = EnrichmentResult(
        ioc=IOC("https://example.com/?access_token=private-value", IOCType.URL),
        isp="configured-api-secret",
        sources={"provider": {"message": "configured-api-secret"}},
    )
    clean = sanitize_result_for_output(result, ("configured-api-secret",))
    assert clean.ioc.value == "https://example.com/"
    assert clean.isp == "[REDACTED]"
    assert clean.sources["provider"]["message"] == "[REDACTED]"
    assert result.ioc.value.endswith("access_token=private-value")
    assert sanitize_sensitive_data({"client_secret": "unknown-secret"}) == {
        "client_secret": "[REDACTED]"
    }
