"""
URLScan.io Enricher — URL/domain scanning and screenshot service.
Supports: URL, Domain
Free tier: 5,000 scans/day (search is free)
https://urlscan.io/docs/api/
"""

from src.models import IOC, IOCType, EnrichmentResult
from src.enrichers.base import BaseEnricher
from src.utils.security import allowlisted_object, api_country, api_integer, api_public_ip, api_text, validate_ioc, IOCValidationError


class URLScanEnricher(BaseEnricher):
    name = "urlscan"
    supports = [IOCType.URL, IOCType.DOMAIN]

    SEARCH_URL = "https://urlscan.io/api/v1/search/"
    allowed_hosts = {"urlscan.io"}

    def is_available(self) -> bool:
        # URLScan search is free without a key; key only needed for submissions
        return True

    def _headers(self) -> dict:
        h = {"Content-Type": "application/json"}
        if self.api_key:
            h["API-Key"] = self.api_key
        return h

    def enrich(self, ioc: IOC, result: EnrichmentResult) -> EnrichmentResult:
        if ioc.ioc_type == IOCType.URL:
            escaped_url = ioc.value.replace("\\", "\\\\").replace('"', '\\"')
            query = f'page.url:"{escaped_url}"'
        elif ioc.ioc_type == IOCType.DOMAIN:
            query = f'domain:{ioc.value}'
        else:
            return result

        data = self.get(
            self.SEARCH_URL,
            params={"q": query, "size": 5},
            headers=self._headers(),
        )

        results = data.get("results") if isinstance(data, dict) else None
        if not isinstance(results, list) or not results:
            result.errors[self.name] = "No scan results found"
            return result

        latest = allowlisted_object(results[0], {"page", "verdicts", "_id", "screenshot"})
        page = allowlisted_object(latest.get("page"), {"url", "domain", "ip", "country", "server"})
        verdicts = allowlisted_object(latest.get("verdicts"), {"overall"})
        overall = allowlisted_object(verdicts.get("overall"), {"malicious", "score"})
        score = api_integer(overall.get("score"), maximum=100)
        if score is None or not isinstance(overall.get("malicious", False), bool):
            result.errors[self.name] = "Provider response did not match the supported schema"
            return result

        result.urlscan_verdict = (
            "Malicious" if overall.get("malicious") else
            "Suspicious" if score > 30 else "Clean"
        )
        screenshot = api_text(latest.get("screenshot"), max_length=2048)
        try:
            result.urlscan_screenshot = validate_ioc(screenshot, IOCType.URL) if screenshot else None
        except IOCValidationError:
            result.urlscan_screenshot = None

        # Propagate verdict
        if result.urlscan_verdict == "Malicious":
            result.malicious_votes = max(result.malicious_votes, 1)
        elif result.urlscan_verdict == "Suspicious":
            result.suspicious_votes = max(result.suspicious_votes, 1)

        result.sources[self.name] = {
            "verdict": result.urlscan_verdict,
            "score": score,
            "screenshot": result.urlscan_screenshot,
            "server": api_text(page.get("server"), max_length=256),
            "ip": api_public_ip(page.get("ip")),
            "country": api_country(page.get("country")),
            "scan_id": api_text(latest.get("_id"), max_length=128),
        }

        if not result.country:
            result.country = api_country(page.get("country"))

        return result
