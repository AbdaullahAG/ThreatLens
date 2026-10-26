"""
AlienVault OTX Enricher — Open Threat Exchange.
Supports: IP, Domain, URL, Hash
Free tier: unlimited public pulse lookups
https://otx.alienvault.com/api
"""

from src.models import IOC, IOCType, EnrichmentResult
from src.enrichers.base import BaseEnricher
from src.utils.security import allowlisted_object, api_country, api_integer, api_text


class OTXEnricher(BaseEnricher):
    name = "otx"
    supports = [IOCType.IP, IOCType.DOMAIN, IOCType.URL, IOCType.HASH]

    BASE_URL = "https://otx.alienvault.com/api/v1/indicators"
    allowed_hosts = {"otx.alienvault.com"}

    def is_available(self) -> bool:
        return bool(self.api_key)

    def _headers(self) -> dict:
        return {"X-OTX-API-KEY": self.api_key}

    def _get_section(self, ioc_type: str, ioc_value: str, section: str) -> dict | None:
        url = f"{self.BASE_URL}/{ioc_type}/{ioc_value}/{section}"
        data = self.get(url, headers=self._headers())
        if not isinstance(data, dict):
            return None
        return allowlisted_object(
            data,
            {"pulse_info", "country_code", "country_name", "asn", "reputation", "alexa", "analysis"},
        )

    @staticmethod
    def _pulse_count(general: dict) -> int | None:
        pulse_info = allowlisted_object(general.get("pulse_info"), {"count"})
        return api_integer(pulse_info.get("count"), maximum=1_000_000)

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

        pulse_count = self._pulse_count(general)
        if pulse_count is None:
            result.errors[self.name] = "Provider response did not match the supported schema"
            return result

        if not result.country:
            result.country = api_country(general.get("country_code"))
        if not result.asn:
            result.asn = api_text(general.get("asn"), max_length=32)

        result.sources[self.name] = {
            "pulse_count": pulse_count,
            "country": api_text(general.get("country_name"), max_length=128),
            "reputation": api_integer(general.get("reputation"), minimum=-10_000, maximum=10_000),
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

        pulse_count = self._pulse_count(general)
        if pulse_count is None:
            result.errors[self.name] = "Provider response did not match the supported schema"
            return result

        result.sources[self.name] = {
            "pulse_count": pulse_count,
            "alexa": api_integer(general.get("alexa"), maximum=100_000_000),
        }
        if pulse_count > 0:
            result.malicious_votes = max(result.malicious_votes, 1)
        return result

    def _enrich_url(self, ioc: IOC, result: EnrichmentResult) -> EnrichmentResult:
        # OTX URL lookup uses domain extraction
        from urllib.parse import urlsplit
        domain = urlsplit(ioc.value).hostname
        if not domain:
            return result
        return self._enrich_domain(
            IOC(value=domain, ioc_type=IOCType.DOMAIN), result
        )

    def _enrich_hash(self, ioc: IOC, result: EnrichmentResult) -> EnrichmentResult:
        # Only supported hash lengths are accepted.
        length = len(ioc.value)
        if length not in (32, 40, 64):
            return result

        general = self._get_section("file", ioc.value, "general")
        if not general:
            result.errors[self.name] = "No data"
            return result

        pulse_count = self._pulse_count(general)
        if pulse_count is None:
            result.errors[self.name] = "Provider response did not match the supported schema"
            return result

        analysis = allowlisted_object(general.get("analysis"), {"info"})
        info = allowlisted_object(analysis.get("info"), {"results"})
        analysis_results = allowlisted_object(info.get("results"), {"file_class"})
        result.sources[self.name] = {
            "pulse_count": pulse_count,
            "file_class": api_text(analysis_results.get("file_class"), max_length=128),
        }
        if pulse_count > 0:
            result.malicious_votes = max(result.malicious_votes, 1)
            result.positives = max(result.positives, 1)
        return result
