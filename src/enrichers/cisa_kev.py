"""
CISA KEV Enricher — CISA Known Exploited Vulnerabilities catalog.
Supports: CVE
Free, no API key required.
https://www.cisa.gov/known-exploited-vulnerabilities-catalog

The catalog is a single large JSON document (~1600+ entries) rather than a
per-CVE lookup endpoint, so this enricher downloads it once and caches the
parsed result locally via the investigation store, refreshing on a TTL
instead of hitting CISA on every IOC.
"""

from __future__ import annotations

import time
from typing import Optional

from src.models import IOC, IOCType, EnrichmentResult
from src.enrichers.base import BaseEnricher

FEED_NAME = "cisa_kev"


class CISAKEVEnricher(BaseEnricher):
    name = "cisa_kev"
    supports = [IOCType.CVE]

    FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    allowed_hosts = {"www.cisa.gov"}

    # Default TTL used only when no store/config TTL is supplied.
    default_ttl_seconds = 24 * 60 * 60

    def is_available(self) -> bool:
        return True  # Free, no key required

    def enrich(self, ioc: IOC, result: EnrichmentResult) -> EnrichmentResult:
        if ioc.ioc_type != IOCType.CVE:
            return result

        catalog = self._load_catalog()
        if catalog is None:
            result.errors[self.name] = "CISA KEV catalog unavailable"
            return result

        entry = catalog.get(ioc.value.upper())
        if entry is None:
            # Explicitly record a "not listed" success so downstream decision
            # logic can distinguish "checked, not in KEV" from "lookup failed".
            result.cisa_kev = False
            result.sources[self.name] = {"listed": False}
            return result

        result.cisa_kev = True
        result.cisa_kev_due_date = entry.get("due_date")
        result.cisa_kev_ransomware_use = str(entry.get("ransomware_use", "")).lower() == "known"
        result.sources[self.name] = {
            "listed": True,
            "vendor_project": entry.get("vendor_project"),
            "product": entry.get("product"),
            "vulnerability_name": entry.get("vulnerability_name"),
            "date_added": entry.get("date_added"),
            "due_date": entry.get("due_date"),
            "required_action": entry.get("required_action"),
            "ransomware_use": entry.get("ransomware_use"),
        }
        return result

    # ------------------------------------------------------------------
    # Feed caching
    # ------------------------------------------------------------------

    def _load_catalog(self) -> Optional[dict[str, dict]]:
        """Return a dict keyed by CVE ID, using the local cache when fresh."""
        now = int(time.time())

        if self.store is not None:
            cached = self.store.get_cached_feed(FEED_NAME, now)
            if cached is not None:
                return cached

        raw = self.get(self.FEED_URL)
        if not raw or "vulnerabilities" not in raw:
            return None

        catalog: dict[str, dict] = {}
        for item in raw.get("vulnerabilities", []):
            if not isinstance(item, dict):
                continue
            cve_id = item.get("cveID")
            if not cve_id:
                continue
            catalog[str(cve_id).upper()] = {
                "vendor_project": item.get("vendorProject"),
                "product": item.get("product"),
                "vulnerability_name": item.get("vulnerabilityName"),
                "date_added": item.get("dateAdded"),
                "short_description": item.get("shortDescription"),
                "required_action": item.get("requiredAction"),
                "due_date": item.get("dueDate"),
                "ransomware_use": item.get("knownRansomwareCampaignUse"),
            }

        if self.store is not None:
            ttl = getattr(self, "cache_ttl_seconds", self.default_ttl_seconds)
            self.store.cache_feed(FEED_NAME, catalog, now, now + ttl)

        return catalog
