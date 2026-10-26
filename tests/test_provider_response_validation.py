"""Provider schema allow-list tests against mocked untrusted JSON responses."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from src.enrichers.abuseipdb import AbuseIPDBEnricher
from src.enrichers.epss import EPSSEnricher
from src.enrichers.shodan import ShodanEnricher
from src.enrichers.virustotal import VirusTotalEnricher
from src.enrichers.urlscan import URLScanEnricher
from src.models import EnrichmentResult, IOC, IOCType


def _response(body: dict) -> MagicMock:
    response = MagicMock()
    response.status_code = 200
    encoded = json.dumps(body).encode("utf-8")
    response.headers = {"Content-Type": "application/json", "Content-Length": str(len(encoded))}
    response.iter_content.return_value = [encoded]
    return response


def test_abuseipdb_rejects_out_of_range_reputation_values():
    enricher = AbuseIPDBEnricher(api_key="api-secret", delay=0)
    with patch.object(enricher.session, "get", return_value=_response({"data": {"abuseConfidenceScore": 10_000}})):
        result = enricher.enrich(IOC("8.8.8.8", IOCType.IP), EnrichmentResult(ioc=IOC("8.8.8.8", IOCType.IP)))
    assert result.sources == {}
    assert "abuseipdb" in result.errors


def test_shodan_keeps_only_bounded_ports_and_cve_identifiers():
    enricher = ShodanEnricher(api_key="api-secret", delay=0)
    payload = {"ports": [22, -1, 70_000, "443"], "vulns": {"CVE-2021-44228": {}, "not-a-cve": {}}, "unexpected": "ignored"}
    with patch.object(enricher.session, "get", return_value=_response(payload)):
        result = enricher.enrich(IOC("8.8.8.8", IOCType.IP), EnrichmentResult(ioc=IOC("8.8.8.8", IOCType.IP)))
    assert result.open_ports == [22]
    assert result.shodan_vulns == ["CVE-2021-44228"]
    assert "unexpected" not in result.sources["shodan"]


def test_virustotal_rejects_invalid_analysis_statistics():
    enricher = VirusTotalEnricher(api_key="api-secret", delay=0)
    payload = {"data": {"attributes": {"last_analysis_stats": {"malicious": "many", "admin": 99}}}}
    with patch.object(enricher.session, "get", return_value=_response(payload)):
        result = enricher.enrich(IOC("example.com", IOCType.DOMAIN), EnrichmentResult(ioc=IOC("example.com", IOCType.DOMAIN)))
    assert result.sources == {}
    assert "virustotal" in result.errors


def test_urlscan_rejects_invalid_verdict_score():
    enricher = URLScanEnricher(api_key=None, delay=0)
    payload = {"results": [{"page": {}, "verdicts": {"overall": {"malicious": False, "score": "high"}}}]}
    with patch.object(enricher.session, "get", return_value=_response(payload)):
        result = enricher.enrich(IOC("https://example.com/", IOCType.URL), EnrichmentResult(ioc=IOC("https://example.com/", IOCType.URL)))
    assert result.sources == {}
    assert "urlscan" in result.errors


def test_epss_prefetch_validates_and_caps_cve_inputs():
    enricher = EPSSEnricher(api_key=None, delay=0)
    values = (f"CVE-2020-{number:06d}" for number in range(100_000, 101_001))
    with patch.object(enricher, "get", return_value=None) as get:
        enricher.prefetch(iter(["not-a-cve", *values]))

    assert get.call_count == 10  # 1,000 accepted IDs, in batches of 100
    assert all(len(call.kwargs["params"]["cve"].split(",")) == 100 for call in get.call_args_list)
