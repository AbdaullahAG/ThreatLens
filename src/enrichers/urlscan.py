"""
URLScan.io Enricher — URL/domain scanning and screenshot service.
Supports: URL, Domain
Free tier: 5,000 scans/day (search is free)
https://urlscan.io/docs/api/
"""

from src.models import IOC, IOCType, EnrichmentResult
from src.enrichers.base import BaseEnricher


class URLScanEnricher(BaseEnricher):
    name = "urlscan"
    supports = [IOCType.URL, IOCType.DOMAIN]

    SEARCH_URL = "https://urlscan.io/api/v1/search/"

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
            query = f'page.url:"{ioc.value}"'
        elif ioc.ioc_type == IOCType.DOMAIN:
            query = f'domain:{ioc.value}'
        else:
            return result

        data = self.get(
            self.SEARCH_URL,
            params={"q": query, "size": 5},
            headers=self._headers(),
        )

        if not data or not data.get("results"):
            result.errors[self.name] = "No scan results found"
            return result

        latest = data["results"][0]
        page = latest.get("page", {})
        verdicts = latest.get("verdicts", {})
        overall = verdicts.get("overall", {})

        result.urlscan_verdict = (
            "Malicious" if overall.get("malicious") else
            "Suspicious" if overall.get("score", 0) > 30 else "Clean"
        )
        result.urlscan_screenshot = latest.get("screenshot")

        # Propagate verdict
        if result.urlscan_verdict == "Malicious":
            result.malicious_votes = max(result.malicious_votes, 1)
        elif result.urlscan_verdict == "Suspicious":
            result.suspicious_votes = max(result.suspicious_votes, 1)

        result.sources[self.name] = {
            "verdict": result.urlscan_verdict,
            "score": overall.get("score", 0),
            "screenshot": result.urlscan_screenshot,
            "server": page.get("server"),
            "ip": page.get("ip"),
            "country": page.get("country"),
            "scan_id": latest.get("_id"),
        }

        if not result.country:
            result.country = page.get("country")

        return result
