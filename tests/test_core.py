"""
Unit Tests — ThreatLens core components.
Run with: pytest tests/ -v
"""

import pytest
from src.parsers.ioc_parser import IOCParser
from src.models import IOCType, IOC, EnrichmentResult
from src.utils.security import IOCValidationError, spreadsheet_value, validate_ioc
from src.storage import InvestigationStore


# ── IOCParser Tests ──────────────────────────────────────────────────────────

class TestIOCParser:

    def setup_method(self):
        self.parser = IOCParser()

    def test_extract_public_ip(self):
        result = self.parser.parse_text("Connection from 45.33.32.156 detected")
        ips = [i for i in result.iocs if i.ioc_type == IOCType.IP]
        assert any(i.value == "45.33.32.156" for i in ips)

    def test_ignore_private_ip(self):
        result = self.parser.parse_text("Internal host 192.168.1.1 connected")
        ips = [i for i in result.iocs if i.ioc_type == IOCType.IP]
        assert not any(i.value == "192.168.1.1" for i in ips)
        assert "192.168.1.1" in result.ignored_ips

    def test_ignore_loopback(self):
        result = self.parser.parse_text("127.0.0.1 localhost")
        ips = [i for i in result.iocs if i.ioc_type == IOCType.IP]
        assert len(ips) == 0

    def test_extract_domain(self):
        result = self.parser.parse_text("Accessed malware.example.net via DNS")
        domains = [i for i in result.iocs if i.ioc_type == IOCType.DOMAIN]
        assert any("example.net" in i.value for i in domains)

    def test_extract_url(self):
        result = self.parser.parse_text("GET http://evil.com/payload.exe HTTP/1.1")
        urls = [i for i in result.iocs if i.ioc_type == IOCType.URL]
        assert any("evil.com" in i.value for i in urls)

    def test_extract_md5(self):
        result = self.parser.parse_text("File hash: d41d8cd98f00b204e9800998ecf8427e")
        hashes = [i for i in result.iocs if i.ioc_type == IOCType.HASH]
        assert any(i.value == "d41d8cd98f00b204e9800998ecf8427e" for i in hashes)

    def test_extract_sha256(self):
        sha256 = "a" * 64
        result = self.parser.parse_text(f"SHA256: {sha256}")
        hashes = [i for i in result.iocs if i.ioc_type == IOCType.HASH]
        assert any(i.value == sha256 for i in hashes)

    def test_extract_cve(self):
        result = self.parser.parse_text("Exploiting CVE-2021-44228 (Log4Shell)")
        cves = [i for i in result.iocs if i.ioc_type == IOCType.CVE]
        assert any(i.value == "CVE-2021-44228" for i in cves)

    def test_cve_case_insensitive(self):
        result = self.parser.parse_text("vulnerability: cve-2023-1234")
        cves = [i for i in result.iocs if i.ioc_type == IOCType.CVE]
        assert any(i.value == "CVE-2023-1234" for i in cves)

    def test_deduplication(self):
        text = "45.33.32.156 connected again from 45.33.32.156"
        result = self.parser.parse_text(text)
        ips = [i for i in result.iocs if i.ioc_type == IOCType.IP]
        assert len(ips) == 1

    def test_mixed_iocs(self):
        text = (
            "IP: 8.8.8.8 domain: google.com "
            "hash: d41d8cd98f00b204e9800998ecf8427e "
            "CVE-2021-44228"
        )
        result = self.parser.parse_text(text)
        assert result.stats["ip"] >= 1
        assert result.stats["domain"] >= 1
        assert result.stats["hash"] >= 1
        assert result.stats["cve"] >= 1

    def test_from_args_ip(self):
        iocs = IOCParser.from_args(ips=["1.2.3.4", "5.6.7.8"])
        assert len(iocs) == 2
        assert all(i.ioc_type == IOCType.IP for i in iocs)

    def test_from_args_url_detection(self):
        iocs = IOCParser.from_args(domains=["https://example.com/path"])
        assert iocs[0].ioc_type == IOCType.URL

    def test_from_args_domain_detection(self):
        iocs = IOCParser.from_args(domains=["example.com"])
        assert iocs[0].ioc_type == IOCType.DOMAIN

    def test_rejects_invalid_cli_ioc(self):
        with pytest.raises(IOCValidationError):
            IOCParser.from_args(ips=["not-an-ip"])

    def test_rejects_private_cli_ip_by_default(self):
        with pytest.raises(IOCValidationError):
            IOCParser.from_args(ips=["192.168.1.1"])

    def test_allows_private_cli_ip_only_when_explicit(self):
        iocs = IOCParser.from_args(ips=["192.168.1.1"], allow_private=True)
        assert iocs[0].value == "192.168.1.1"

    def test_rejects_url_credentials(self):
        with pytest.raises(IOCValidationError):
            validate_ioc("https://user:password@example.com", IOCType.URL)

    def test_file_limit(self, tmp_path):
        path = tmp_path / "large.log"
        path.write_text("8.8.8.8")
        with pytest.raises(ValueError):
            IOCParser(max_file_bytes=1).parse_file(str(path))

    def test_spreadsheet_formula_is_neutralized(self):
        assert spreadsheet_value("=HYPERLINK(\"https://evil.example\")").startswith("'")
        assert spreadsheet_value(42) == 42


# ── EnrichmentResult Tests ───────────────────────────────────────────────────

class TestEnrichmentResult:

    def _make(self, ioc_type: IOCType, value: str = "test") -> EnrichmentResult:
        result = EnrichmentResult(ioc=IOC(value=value, ioc_type=ioc_type))
        # Existing verdict tests model a successful provider response. A result
        # with no source evidence is intentionally classified as Unknown.
        result.sources["test_provider"] = {"status": "ok"}
        return result

    def test_ip_malicious_verdict(self):
        r = self._make(IOCType.IP)
        r.abuse_score = 90
        r.set_verdict()
        assert r.verdict == "Malicious"

    def test_ip_suspicious_verdict(self):
        r = self._make(IOCType.IP)
        r.abuse_score = 40
        r.set_verdict()
        assert r.verdict == "Suspicious"

    def test_ip_clean_verdict(self):
        r = self._make(IOCType.IP)
        r.abuse_score = 0
        r.set_verdict()
        assert r.verdict == "Clean"

    def test_domain_malicious(self):
        r = self._make(IOCType.DOMAIN)
        r.malicious_votes = 5
        r.set_verdict()
        assert r.verdict == "Malicious"

    def test_domain_clean(self):
        r = self._make(IOCType.DOMAIN)
        r.malicious_votes = 0
        r.suspicious_votes = 0
        r.set_verdict()
        assert r.verdict == "Clean"

    def test_no_successful_source_is_unknown(self):
        r = self._make(IOCType.DOMAIN)
        r.sources.clear()
        r.errors["virustotal"] = "No data"
        r.set_verdict()
        assert r.verdict == "Unknown"
        assert r.confidence_score == 0

    def test_cache_round_trip(self, tmp_path):
        store = InvestigationStore(str(tmp_path / "investigations.db"))
        result = self._make(IOCType.IP, "8.8.8.8")
        result.sources["test"] = {"status": "ok"}
        result.set_verdict()
        store.cache_result(result, expires_at=9_999_999_999)
        cached = store.get_cached(result.ioc, now=1)
        assert cached is not None
        assert cached.ioc.value == "8.8.8.8"

    def test_hash_malicious(self):
        r = self._make(IOCType.HASH)
        r.positives = 50
        r.total_scanners = 70
        r.set_verdict()
        assert r.verdict == "Malicious"

    def test_hash_suspicious(self):
        r = self._make(IOCType.HASH)
        r.positives = 3
        r.total_scanners = 70
        r.set_verdict()
        assert r.verdict == "Suspicious"

    def test_cve_critical(self):
        r = self._make(IOCType.CVE, "CVE-2021-44228")
        r.cvss_score = 10.0
        r.set_verdict()
        assert r.verdict == "Critical"

    def test_cve_high(self):
        r = self._make(IOCType.CVE, "CVE-2021-0001")
        r.cvss_score = 8.5
        r.set_verdict()
        assert r.verdict == "High"

    def test_cve_medium(self):
        r = self._make(IOCType.CVE, "CVE-2021-0002")
        r.cvss_score = 5.0
        r.set_verdict()
        assert r.verdict == "Medium"

    def test_cve_low(self):
        r = self._make(IOCType.CVE, "CVE-2021-0003")
        r.cvss_score = 2.0
        r.set_verdict()
        assert r.verdict == "Low"
