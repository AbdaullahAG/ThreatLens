"""
Shodan Enricher — port scanning and vulnerability data for IPs.
Supports: IP
Free tier: limited lookups (no crawling)
https://developer.shodan.io/api
"""

from src.models import IOC, IOCType, EnrichmentResult
from src.enrichers.base import BaseEnricher


class ShodanEnricher(BaseEnricher):
    name = "shodan"
    supports = [IOCType.IP]

    BASE_URL = "https://api.shodan.io/shodan/host"

    def is_available(self) -> bool:
        return bool(self.api_key)

    def enrich(self, ioc: IOC, result: EnrichmentResult) -> EnrichmentResult:
        if ioc.ioc_type != IOCType.IP:
            return result

        data = self.get(
            f"{self.BASE_URL}/{ioc.value}",
            params={"key": self.api_key},
        )

        if not data:
            result.errors[self.name] = "No data"
            return result

        result.open_ports = data.get("ports", [])
        result.shodan_tags = data.get("tags", [])
        result.organization = data.get("org") or result.organization
        result.asn = data.get("asn") or result.asn

        # Vulnerabilities reported by Shodan
        vulns = data.get("vulns", {})
        result.shodan_vulns = list(vulns.keys()) if vulns else []

        if not result.country:
            result.country = data.get("country_code")

        result.sources[self.name] = {
            "ports": result.open_ports,
            "tags": result.shodan_tags,
            "vulns": result.shodan_vulns,
            "org": result.organization,
            "os": data.get("os"),
            "hostnames": data.get("hostnames", []),
        }

        # Merge hostnames
        existing = set(result.hostnames)
        for h in data.get("hostnames", []):
            if h not in existing:
                result.hostnames.append(h)

        return result
