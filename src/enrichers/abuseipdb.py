"""
AbuseIPDB Enricher — checks IP reputation.
Supports: IP
Free tier: 1,000 checks/day
https://www.abuseipdb.com/api
"""

from src.models import IOC, IOCType, EnrichmentResult
from src.enrichers.base import BaseEnricher
from src.utils.security import allowlisted_object, api_country, api_hostname, api_hostname_list, api_integer, api_text


class AbuseIPDBEnricher(BaseEnricher):
    name = "abuseipdb"
    supports = [IOCType.IP]

    BASE_URL = "https://api.abuseipdb.com/api/v2/check"
    allowed_hosts = {"api.abuseipdb.com"}

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

        d = allowlisted_object(
            data.get("data"),
            {"abuseConfidenceScore", "countryCode", "isp", "domain", "totalReports", "lastReportedAt", "usageType", "hostnames"},
        )
        score = api_integer(d.get("abuseConfidenceScore"), maximum=100)
        if score is None:
            result.errors[self.name] = "Provider response did not match the supported schema"
            return result
        result.abuse_score = score
        result.country = api_country(d.get("countryCode"))
        result.isp = api_text(d.get("isp"))
        result.domain = api_hostname(d.get("domain"))
        result.total_reports = api_integer(d.get("totalReports")) or 0
        result.last_reported = api_text(d.get("lastReportedAt"), max_length=64)
        result.usage_type = api_text(d.get("usageType"), max_length=128)
        result.hostnames = api_hostname_list(d.get("hostnames"), max_items=100)

        # Store raw
        result.sources[self.name] = {
            "abuse_score": result.abuse_score,
            "country": result.country,
            "isp": result.isp,
            "usage_type": result.usage_type,
            "total_reports": result.total_reports,
        }
        return result
