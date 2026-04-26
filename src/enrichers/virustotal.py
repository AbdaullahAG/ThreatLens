"""
VirusTotal Enricher — multi-IOC threat intelligence.
Supports: IP, Domain, URL, Hash
Free tier: 4 lookups/min, 500/day
https://developers.virustotal.com/reference
"""

import base64
import hashlib
from src.models import IOC, IOCType, EnrichmentResult
from src.enrichers.base import BaseEnricher


class VirusTotalEnricher(BaseEnricher):
    name = "virustotal"
    supports = [IOCType.IP, IOCType.DOMAIN, IOCType.URL, IOCType.HASH]

    BASE_URL = "https://www.virustotal.com/api/v3"

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

    def _parse_stats(self, attributes: dict, result: EnrichmentResult):
        """Parse last_analysis_stats into result fields."""
        stats = attributes.get("last_analysis_stats", {})
        result.malicious_votes = stats.get("malicious", 0)
        result.suspicious_votes = stats.get("suspicious", 0)
        result.harmless_votes = stats.get("harmless", 0)
        result.total_scanners = sum(stats.values())

    def _enrich_ip(self, ioc: IOC, result: EnrichmentResult) -> EnrichmentResult:
        data = self.get(
            f"{self.BASE_URL}/ip_addresses/{ioc.value}",
            headers=self._headers(),
        )
        if not data:
            result.errors[self.name] = "No data"
            return result

        attrs = data.get("data", {}).get("attributes", {})
        self._parse_stats(attrs, result)

        # Fill in missing fields from VT
        if not result.country:
            result.country = attrs.get("country")
        if not result.asn:
            result.asn = str(attrs.get("asn", "")) or None
        if not result.organization:
            result.organization = attrs.get("as_owner")

        result.sources[self.name] = {
            "malicious": result.malicious_votes,
            "suspicious": result.suspicious_votes,
            "harmless": result.harmless_votes,
            "country": attrs.get("country"),
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

        attrs = data.get("data", {}).get("attributes", {})
        self._parse_stats(attrs, result)

        categories = attrs.get("categories", {})
        result.categories = list(set(categories.values()))
        result.tags = attrs.get("tags", [])

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

        attrs = data.get("data", {}).get("attributes", {})
        self._parse_stats(attrs, result)

        result.sources[self.name] = {
            "malicious": result.malicious_votes,
            "suspicious": result.suspicious_votes,
            "final_url": attrs.get("last_final_url"),
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

        attrs = data.get("data", {}).get("attributes", {})
        self._parse_stats(attrs, result)

        result.positives = result.malicious_votes
        result.file_name = (attrs.get("meaningful_name") or
                            (attrs.get("names") or [None])[0])
        result.file_type = attrs.get("type_description")
        result.file_size = attrs.get("size")
        result.tags = attrs.get("tags", [])

        result.sources[self.name] = {
            "malicious": result.malicious_votes,
            "total": result.total_scanners,
            "file_type": result.file_type,
            "file_name": result.file_name,
            "size": result.file_size,
        }
        return result
