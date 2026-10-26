"""
Shodan Enricher — port scanning and vulnerability data for IPs.
Supports: IP
Free tier: limited lookups (no crawling)
https://developer.shodan.io/api
"""

from src.models import IOC, IOCType, EnrichmentResult
from src.enrichers.base import BaseEnricher
from src.utils.security import allowlisted_object, api_country, api_cve_list, api_hostname_list, api_integer, api_string_list, api_text


class ShodanEnricher(BaseEnricher):
    name = "shodan"
    supports = [IOCType.IP]

    BASE_URL = "https://api.shodan.io/shodan/host"
    allowed_hosts = {"api.shodan.io"}

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

        data = allowlisted_object(
            data,
            {"ports", "tags", "org", "asn", "vulns", "country_code", "os", "hostnames"},
        )

        raw_ports = data.get("ports")
        if not isinstance(raw_ports, list):
            result.errors[self.name] = "Provider response did not match the supported schema"
            return result
        result.open_ports = [
            safe_port for raw_port in raw_ports[:4096]
            if (safe_port := api_integer(raw_port, minimum=1, maximum=65535)) is not None
        ] if isinstance(raw_ports, list) else []
        result.shodan_tags = api_string_list(data.get("tags"), max_items=100, max_length=128)
        result.organization = api_text(data.get("org"), max_length=512) or result.organization
        result.asn = api_text(data.get("asn"), max_length=32) or result.asn

        # Vulnerabilities reported by Shodan
        vulns = data.get("vulns", {})
        result.shodan_vulns = api_cve_list(list(vulns) if isinstance(vulns, dict) else [])

        if not result.country:
            result.country = api_country(data.get("country_code"))

        result.sources[self.name] = {
            "ports": result.open_ports,
            "tags": result.shodan_tags,
            "vulns": result.shodan_vulns,
            "org": result.organization,
            "os": api_text(data.get("os"), max_length=256),
            "hostnames": api_hostname_list(data.get("hostnames"), max_items=100),
        }

        # Merge hostnames
        existing = set(result.hostnames)
        for h in api_hostname_list(data.get("hostnames"), max_items=100):
            if h not in existing:
                result.hostnames.append(h)

        return result
