"""
AbuseIPDB Enricher — checks IP reputation.
Supports: IP
Free tier: 1,000 checks/day
https://www.abuseipdb.com/api
"""

from src.models import IOC, IOCType, EnrichmentResult
from src.enrichers.base import BaseEnricher


class AbuseIPDBEnricher(BaseEnricher):
    name = "abuseipdb"
    supports = [IOCType.IP]

    BASE_URL = "https://api.abuseipdb.com/api/v2/check"

    def is_available(self) -> bool:
        return bool(self.api_key)

    def enrich(self, ioc: IOC, result: EnrichmentResult) -> EnrichmentResult:
        if ioc.ioc_type != IOCType.IP:
            return result

        data = self.get(
            self.BASE_URL,
            params={"ipAddress": ioc.value, "maxAgeInDays": "90", "verbose": "true"},
            headers={"Key": self.api_key, "Accept": "application/json"},
        )

        if not data or "data" not in data:
            result.errors[self.name] = "No data returned"
            return result

        d = data["data"]
        result.abuse_score = d.get("abuseConfidenceScore", 0)
        result.country = d.get("countryCode")
        result.isp = d.get("isp")
        result.domain = d.get("domain")
        result.total_reports = d.get("totalReports", 0)
        result.last_reported = d.get("lastReportedAt")
        result.usage_type = d.get("usageType")
        result.hostnames = d.get("hostnames") or []

        # Store raw
        result.sources[self.name] = {
            "abuse_score": result.abuse_score,
            "country": result.country,
            "isp": result.isp,
            "usage_type": result.usage_type,
            "total_reports": result.total_reports,
        }
        return result
