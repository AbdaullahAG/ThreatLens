"""
Unit tests for the CISA KEV and EPSS enrichers, and the InvestigationStore
feed-cache methods that back CISA KEV's local caching.
"""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest

from src.enrichers.cisa_kev import CISAKEVEnricher
from src.enrichers.epss import EPSSEnricher
from src.models import IOC, IOCType, EnrichmentResult
from src.storage import InvestigationStore


def _mock_response(status: int, body: dict, content_type: str = "application/json") -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.headers = {"Content-Type": content_type}
    resp.json.return_value = body
    return resp


KEV_FEED = {
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-44228",
            "vendorProject": "Apache",
            "product": "Log4j2",
            "vulnerabilityName": "Log4Shell",
            "dateAdded": "2021-12-10",
            "shortDescription": "RCE via JNDI lookup",
            "requiredAction": "Apply updates",
            "dueDate": "2021-12-24",
            "knownRansomwareCampaignUse": "Known",
        }
    ]
}


class TestCISAKEVEnricher:
    def _enricher(self, store=None):
        return CISAKEVEnricher(api_key=None, timeout=5, delay=0.0, store=store)

    def test_listed_cve_marks_kev(self):
        enricher = self._enricher()
        with patch.object(enricher.session, "get", return_value=_mock_response(200, KEV_FEED)):
            result = EnrichmentResult(ioc=IOC("CVE-2021-44228", IOCType.CVE))
            result = enricher.enrich(IOC("CVE-2021-44228", IOCType.CVE), result)
        assert result.cisa_kev is True
        assert result.cisa_kev_due_date == "2021-12-24"
        assert result.cisa_kev_ransomware_use is True

    def test_unlisted_cve_not_kev(self):
        enricher = self._enricher()
        with patch.object(enricher.session, "get", return_value=_mock_response(200, KEV_FEED)):
            result = EnrichmentResult(ioc=IOC("CVE-2099-00001", IOCType.CVE))
            result = enricher.enrich(IOC("CVE-2099-00001", IOCType.CVE), result)
        assert result.cisa_kev is False
        assert result.sources["cisa_kev"] == {"listed": False}

    def test_non_cve_ioc_is_noop(self):
        enricher = self._enricher()
        result = EnrichmentResult(ioc=IOC("8.8.8.8", IOCType.IP))
        out = enricher.enrich(IOC("8.8.8.8", IOCType.IP), result)
        assert out.cisa_kev is False
        assert "cisa_kev" not in out.sources

    def test_feed_download_failure_records_error(self):
        enricher = self._enricher()
        with patch.object(enricher.session, "get", return_value=_mock_response(500, {})):
            result = EnrichmentResult(ioc=IOC("CVE-2021-44228", IOCType.CVE))
            result = enricher.enrich(IOC("CVE-2021-44228", IOCType.CVE), result)
        assert "cisa_kev" in result.errors

    def test_uses_local_cache_and_skips_second_download(self, tmp_path):
        store = InvestigationStore(str(tmp_path / "kev_cache.db"))
        enricher = self._enricher(store=store)
        with patch.object(enricher.session, "get", return_value=_mock_response(200, KEV_FEED)) as mock_get:
            enricher.enrich(IOC("CVE-2021-44228", IOCType.CVE), EnrichmentResult(ioc=IOC("CVE-2021-44228", IOCType.CVE)))
            enricher.enrich(IOC("CVE-2021-44228", IOCType.CVE), EnrichmentResult(ioc=IOC("CVE-2021-44228", IOCType.CVE)))
        assert mock_get.call_count == 1

    def test_missing_fields_are_tolerated(self):
        """CISA may add/omit fields; the enricher must not crash on missing ones."""
        feed = {"vulnerabilities": [{"cveID": "CVE-2020-0001"}]}
        enricher = self._enricher()
        with patch.object(enricher.session, "get", return_value=_mock_response(200, feed)):
            result = EnrichmentResult(ioc=IOC("CVE-2020-0001", IOCType.CVE))
            result = enricher.enrich(IOC("CVE-2020-0001", IOCType.CVE), result)
        assert result.cisa_kev is True
        assert result.cisa_kev_due_date is None
        assert result.cisa_kev_ransomware_use is False


EPSS_BODY = {
    "data": [
        {"cve": "CVE-2021-44228", "epss": "0.97", "percentile": "0.99"},
    ]
}


class TestEPSSEnricher:
    def _enricher(self):
        return EPSSEnricher(api_key=None, timeout=5, delay=0.0)

    def test_single_lookup(self):
        enricher = self._enricher()
        with patch.object(enricher.session, "get", return_value=_mock_response(200, EPSS_BODY)):
            result = EnrichmentResult(ioc=IOC("CVE-2021-44228", IOCType.CVE))
            result = enricher.enrich(IOC("CVE-2021-44228", IOCType.CVE), result)
        assert result.epss_score == pytest.approx(0.97)
        assert result.epss_percentile == pytest.approx(0.99)

    def test_prefetch_batches_and_avoids_second_request(self):
        enricher = self._enricher()
        with patch.object(enricher.session, "get", return_value=_mock_response(200, EPSS_BODY)) as mock_get:
            enricher.prefetch(["CVE-2021-44228", "CVE-2021-44228"])
            result = EnrichmentResult(ioc=IOC("CVE-2021-44228", IOCType.CVE))
            enricher.enrich(IOC("CVE-2021-44228", IOCType.CVE), result)
        assert mock_get.call_count == 1
        assert result.epss_score == pytest.approx(0.97)

    def test_no_data_records_error(self):
        enricher = self._enricher()
        with patch.object(enricher.session, "get", return_value=_mock_response(200, {"data": []})):
            result = EnrichmentResult(ioc=IOC("CVE-2021-44228", IOCType.CVE))
            result = enricher.enrich(IOC("CVE-2021-44228", IOCType.CVE), result)
        assert "epss" in result.errors

    def test_non_cve_ioc_is_noop(self):
        enricher = self._enricher()
        result = EnrichmentResult(ioc=IOC("evil.com", IOCType.DOMAIN))
        out = enricher.enrich(IOC("evil.com", IOCType.DOMAIN), result)
        assert out.epss_score is None


class TestFeedCache:
    def test_cache_roundtrip_and_expiry(self, tmp_path):
        store = InvestigationStore(str(tmp_path / "cache.db"))
        now = int(time.time())
        store.cache_feed("demo", {"a": 1}, now, now + 100)
        assert store.get_cached_feed("demo", now) == {"a": 1}
        assert store.get_cached_feed("demo", now + 200) is None

    def test_cache_overwrite(self, tmp_path):
        store = InvestigationStore(str(tmp_path / "cache.db"))
        now = int(time.time())
        store.cache_feed("demo", {"a": 1}, now, now + 100)
        store.cache_feed("demo", {"a": 2}, now, now + 100)
        assert store.get_cached_feed("demo", now) == {"a": 2}
