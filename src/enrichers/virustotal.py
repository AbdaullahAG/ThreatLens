"""
VirusTotal Enricher — multi-IOC threat intelligence.
Supports: IP, Domain, URL, Hash
Free tier: 4 lookups/min, 500/day
https://developers.virustotal.com/reference
"""

import base64
from src.models import IOC, IOCType, EnrichmentResult
from src.enrichers.base import BaseEnricher
from src.utils.security import allowlisted_object, api_country, api_integer, api_mapping_values, api_string_list, api_text


class VirusTotalEnricher(BaseEnricher):
    name = "virustotal"
    supports = [IOCType.IP, IOCType.DOMAIN, IOCType.URL, IOCType.HASH]

    BASE_URL = "https://www.virustotal.com/api/v3"
    allowed_hosts = {"www.virustotal.com"}

    def is_available(self) -> bool:
        return bool(self.api_key)

    def _headers(self) -> dict:
        return {"x-apikey": self.api_key}

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

    def _parse_stats(self, attributes: dict, result: EnrichmentResult) -> bool:
        """Parse last_analysis_stats into result fields."""
        stats = allowlisted_object(
            attributes.get("last_analysis_stats"),
            {"malicious", "suspicious", "harmless", "undetected", "timeout", "failure", "confirmed-timeout"},
        )
        counts = {
            key: parsed
            for key, value in stats.items()
            if (parsed := api_integer(value, maximum=100_000)) is not None
        }
        if not counts:
            return False
        result.malicious_votes = counts.get("malicious", 0)
        result.suspicious_votes = counts.get("suspicious", 0)
        result.harmless_votes = counts.get("harmless", 0)
        result.total_scanners = sum(counts.values())
        return True

    @staticmethod
    def _attributes(data: dict) -> dict:
        """Select only VT fields consumed by this client."""
        root = allowlisted_object(data.get("data"), {"attributes"})
        return allowlisted_object(
            root.get("attributes"),
            {
                "last_analysis_stats", "country", "asn", "as_owner", "categories", "tags",
                "last_final_url", "meaningful_name", "names", "type_description", "size",
            },
        )

    def _enrich_ip(self, ioc: IOC, result: EnrichmentResult) -> EnrichmentResult:
        data = self.get(
            f"{self.BASE_URL}/ip_addresses/{ioc.value}",
            headers=self._headers(),
        )
        if not data:
            result.errors[self.name] = "No data"
            return result

        attrs = self._attributes(data)
        if not self._parse_stats(attrs, result):
            result.errors[self.name] = "Provider response did not match the supported schema"
            return result

        # Fill in missing fields from VT
        if not result.country:
            result.country = api_country(attrs.get("country"))
        if not result.asn:
            asn = attrs.get("asn")
            safe_asn = api_integer(asn, maximum=4_294_967_295)
            result.asn = str(safe_asn) if safe_asn is not None else None
        if not result.organization:
            result.organization = api_text(attrs.get("as_owner"), max_length=512)

        result.sources[self.name] = {
            "malicious": result.malicious_votes,
            "suspicious": result.suspicious_votes,
            "harmless": result.harmless_votes,
            "country": api_country(attrs.get("country")),
        }
        return result

    def _enrich_domain(self, ioc: IOC, result: EnrichmentResult) -> EnrichmentResult:
        data = self.get(
            f"{self.BASE_URL}/domains/{ioc.value}",
            headers=self._headers(),
        )
        if not data:
            result.errors[self.name] = "No data"
            return result

        attrs = self._attributes(data)
        if not self._parse_stats(attrs, result):
            result.errors[self.name] = "Provider response did not match the supported schema"
            return result

        result.categories = sorted(set(api_mapping_values(attrs.get("categories"), max_items=100, max_length=256)))
        result.tags = api_string_list(attrs.get("tags"), max_items=100, max_length=128)

        result.sources[self.name] = {
            "malicious": result.malicious_votes,
            "suspicious": result.suspicious_votes,
            "categories": result.categories,
        }
        return result

    def _enrich_url(self, ioc: IOC, result: EnrichmentResult) -> EnrichmentResult:
        # VT requires URL to be base64url-encoded (no padding)
        url_id = base64.urlsafe_b64encode(ioc.value.encode()).decode().rstrip("=")
        data = self.get(
            f"{self.BASE_URL}/urls/{url_id}",
            headers=self._headers(),
        )
        if not data:
            result.errors[self.name] = "No data"
            return result

        attrs = self._attributes(data)
        if not self._parse_stats(attrs, result):
            result.errors[self.name] = "Provider response did not match the supported schema"
            return result

        result.sources[self.name] = {
            "malicious": result.malicious_votes,
            "suspicious": result.suspicious_votes,
            "final_url": api_text(attrs.get("last_final_url"), max_length=2048),
        }
        return result

    def _enrich_hash(self, ioc: IOC, result: EnrichmentResult) -> EnrichmentResult:
        data = self.get(
            f"{self.BASE_URL}/files/{ioc.value}",
            headers=self._headers(),
        )
        if not data:
            result.errors[self.name] = "No data"
            return result

        attrs = self._attributes(data)
        if not self._parse_stats(attrs, result):
            result.errors[self.name] = "Provider response did not match the supported schema"
            return result

        result.positives = result.malicious_votes
        result.file_name = api_text(attrs.get("meaningful_name"), max_length=512)
        if result.file_name is None:
            names = api_string_list(attrs.get("names"), max_items=100, max_length=512)
            result.file_name = names[0] if names else None
        result.file_type = api_text(attrs.get("type_description"), max_length=128)
        result.file_size = api_integer(attrs.get("size"), maximum=10**15)
        result.tags = api_string_list(attrs.get("tags"), max_items=100, max_length=128)

        result.sources[self.name] = {
            "malicious": result.malicious_votes,
            "total": result.total_scanners,
            "file_type": result.file_type,
            "file_name": result.file_name,
            "size": result.file_size,
        }
        return result
