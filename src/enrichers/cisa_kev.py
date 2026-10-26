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
import re
from datetime import date
from typing import Optional

from src.models import IOC, IOCType, EnrichmentResult
from src.enrichers.base import BaseEnricher
from src.utils.security import allowlisted_object, api_cve, api_text

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
        result.cisa_kev_ransomware_use = entry.get("ransomware_use") == "Known"
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
                clean_cache = self._validate_cached_catalog(cached)
                if clean_cache is not None:
                    return clean_cache

        raw = self.get(self.FEED_URL)
        if not raw or "vulnerabilities" not in raw:
            return None

        catalog: dict[str, dict] = {}
        raw_items = raw.get("vulnerabilities")
        if not isinstance(raw_items, list) or len(raw_items) > 10_000:
            return None
        for raw_item in raw_items:
            item = allowlisted_object(
                raw_item,
                {"cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded", "shortDescription", "requiredAction", "dueDate", "knownRansomwareCampaignUse"},
            )
            cve_id = api_cve(item.get("cveID"))
            if cve_id is None:
                continue
            if not self._valid_date(item.get("dateAdded")):
                continue
            due_date = item.get("dueDate")
            if due_date is not None and not self._valid_date(due_date):
                due_date = None
            ransomware_use = item.get("knownRansomwareCampaignUse")
            if ransomware_use not in {"Known", "Unknown"}:
                ransomware_use = "Unknown"
            catalog[cve_id] = {
                "vendor_project": api_text(item.get("vendorProject"), max_length=256),
                "product": api_text(item.get("product"), max_length=256),
                "vulnerability_name": api_text(item.get("vulnerabilityName"), max_length=256),
                "date_added": item["dateAdded"],
                "short_description": api_text(item.get("shortDescription"), max_length=2048),
                "required_action": api_text(item.get("requiredAction"), max_length=2048),
                "due_date": due_date,
                "ransomware_use": ransomware_use,
            }

        if self.store is not None:
            ttl = getattr(self, "cache_ttl_seconds", self.default_ttl_seconds)
            self.store.cache_feed(FEED_NAME, catalog, now, now + ttl)

        return catalog

    @staticmethod
    def _valid_date(value: object) -> bool:
        """Accept calendar-valid ISO dates from the CISA feed."""
        if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
            return False
        try:
            date.fromisoformat(value)
            return True
        except ValueError:
            return False

    @classmethod
    def _validate_cached_catalog(cls, value: object) -> dict[str, dict] | None:
        """Revalidate normalized feed-cache data before using local persisted values."""
        if not isinstance(value, dict) or len(value) > 10_000:
            return None
        catalog: dict[str, dict] = {}
        allowed = {
            "vendor_project", "product", "vulnerability_name", "date_added",
            "short_description", "required_action", "due_date", "ransomware_use",
        }
        for raw_id, raw_entry in value.items():
            cve_id = api_cve(raw_id)
            entry = allowlisted_object(raw_entry, allowed)
            if cve_id is None or not cls._valid_date(entry.get("date_added")):
                continue
            due_date = entry.get("due_date")
            if due_date is not None and not cls._valid_date(due_date):
                due_date = None
            ransomware_use = entry.get("ransomware_use")
            if ransomware_use not in {"Known", "Unknown"}:
                ransomware_use = "Unknown"
            catalog[cve_id] = {
                "vendor_project": api_text(entry.get("vendor_project"), max_length=256),
                "product": api_text(entry.get("product"), max_length=256),
                "vulnerability_name": api_text(entry.get("vulnerability_name"), max_length=256),
                "date_added": entry["date_added"],
                "short_description": api_text(entry.get("short_description"), max_length=2048),
                "required_action": api_text(entry.get("required_action"), max_length=2048),
                "due_date": due_date,
                "ransomware_use": ransomware_use,
            }
        return catalog
