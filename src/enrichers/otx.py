"""
AlienVault OTX Enricher — Open Threat Exchange.
Supports: IP, Domain, URL, Hash
Free tier: unlimited public pulse lookups
https://otx.alienvault.com/api
"""

from src.models import IOC, IOCType, EnrichmentResult
from src.enrichers.base import BaseEnricher


class OTXEnricher(BaseEnricher):
    name = "otx"
    supports = [IOCType.IP, IOCType.DOMAIN, IOCType.URL, IOCType.HASH]

    BASE_URL = "https://otx.alienvault.com/api/v1/indicators"

    def is_available(self) -> bool:
        return bool(self.api_key)

    def _headers(self) -> dict:
        return {"X-OTX-API-KEY": self.api_key}

    def _get_section(self, ioc_type: str, ioc_value: str, section: str) -> dict | None:
        url = f"{self.BASE_URL}/{ioc_type}/{ioc_value}/{section}"
        return self.get(url, headers=self._headers())

    def enrich(self, ioc: IOC, result: EnrichmentResult) -> EnrichmentResult:
        if ioc.ioc_type == IOCType.IP:
            return self._enrich_ip(ioc, result)
        elif ioc.ioc_type == IOCType.DOMAIN:
            return self._enrich_domain(ioc, result)
        elif ioc.ioc_type == IOCType.URL:
            return self._enrich_url(ioc, result)
        elif ioc.ioc_type == IOCType.HASH:
            return self._enrich_hash(ioc, result)
        return result

    def _enrich_ip(self, ioc: IOC, result: EnrichmentResult) -> EnrichmentResult:
        general = self._get_section("IPv4", ioc.value, "general")
        if not general:
            result.errors[self.name] = "No data"
            return result

        pulse_info = general.get("pulse_info", {})
        pulse_count = pulse_info.get("count", 0)

        if not result.country:
            result.country = general.get("country_code")
        if not result.asn:
            result.asn = general.get("asn")

        result.sources[self.name] = {
            "pulse_count": pulse_count,
            "country": general.get("country_name"),
            "reputation": general.get("reputation", 0),
        }

        # Increase malicious vote count based on OTX pulses
        if pulse_count > 0:
            result.malicious_votes = max(result.malicious_votes, pulse_count)
        return result

    def _enrich_domain(self, ioc: IOC, result: EnrichmentResult) -> EnrichmentResult:
        general = self._get_section("domain", ioc.value, "general")
        if not general:
            result.errors[self.name] = "No data"
            return result

        pulse_info = general.get("pulse_info", {})
        pulse_count = pulse_info.get("count", 0)

        result.sources[self.name] = {
            "pulse_count": pulse_count,
            "alexa": general.get("alexa"),
        }
        if pulse_count > 0:
            result.malicious_votes = max(result.malicious_votes, 1)
        return result

    def _enrich_url(self, ioc: IOC, result: EnrichmentResult) -> EnrichmentResult:
        # OTX URL lookup uses domain extraction
        from urllib.parse import urlparse
        domain = urlparse(ioc.value).netloc
        if not domain:
            return result
        return self._enrich_domain(
            IOC(value=domain, ioc_type=IOCType.DOMAIN), result
        )

    def _enrich_hash(self, ioc: IOC, result: EnrichmentResult) -> EnrichmentResult:
        # Determine hash type by length
        length = len(ioc.value)
        if length == 32:
            hash_type = "file"
            section_val = ioc.value
        elif length == 40:
            hash_type = "file"
            section_val = ioc.value
        elif length == 64:
            hash_type = "file"
            section_val = ioc.value
        else:
            return result

        general = self._get_section("file", ioc.value, "general")
        if not general:
            result.errors[self.name] = "No data"
            return result

        pulse_info = general.get("pulse_info", {})
        pulse_count = pulse_info.get("count", 0)

        result.sources[self.name] = {
            "pulse_count": pulse_count,
            "file_class": general.get("analysis", {}).get("info", {}).get("results", {}).get("file_class"),
        }
        if pulse_count > 0:
            result.malicious_votes = max(result.malicious_votes, 1)
            result.positives = max(result.positives, 1)
        return result
