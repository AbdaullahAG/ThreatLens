"""
EPSS Enricher — FIRST.org Exploit Prediction Scoring System.
Supports: CVE
Free, no API key required.
https://www.first.org/epss/api

Supports batch prefetching: pass a full list of CVE IDs to ``prefetch()``
before running per-IOC enrichment so a single scan of many CVEs performs a
handful of comma-separated requests instead of one request per CVE.
"""

from __future__ import annotations

from typing import Iterable

from src.models import IOC, IOCType, EnrichmentResult
from src.enrichers.base import BaseEnricher
from src.utils.security import allowlisted_object, api_cve, api_probability

# FIRST.org accepts a comma-separated CVE list; keep batches modest to stay
# well under typical URL / query-string length limits.
_BATCH_SIZE = 100
_MAX_PREFETCH_CVES = 1_000


class EPSSEnricher(BaseEnricher):
    name = "epss"
    supports = [IOCType.CVE]

    BASE_URL = "https://api.first.org/data/v1/epss"
    allowed_hosts = {"api.first.org"}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._cache: dict[str, dict] = {}

    def is_available(self) -> bool:
        return True  # Free, no key required

    def prefetch(self, cves: Iterable[str]) -> None:
        """Batch-fetch EPSS scores for many CVEs ahead of per-IOC enrichment."""
        accepted: set[str] = set()
        for value in cves:
            cve_id = api_cve(value)
            if cve_id:
                accepted.add(cve_id)
            if len(accepted) >= _MAX_PREFETCH_CVES:
                break
        unique = sorted(accepted)
        for start in range(0, len(unique), _BATCH_SIZE):
            batch = unique[start:start + _BATCH_SIZE]
            data = self.get(self.BASE_URL, params={"cve": ",".join(batch)})
            if not data:
                continue
            rows = data.get("data")
            if not isinstance(rows, list):
                continue
            requested = set(batch)
            for raw_row in rows[:_BATCH_SIZE]:
                row = allowlisted_object(raw_row, {"cve", "epss", "percentile"})
                cve_id = api_cve(row.get("cve"))
                if cve_id in requested and api_probability(row.get("epss")) is not None:
                    self._cache[cve_id] = row

    def enrich(self, ioc: IOC, result: EnrichmentResult) -> EnrichmentResult:
        if ioc.ioc_type != IOCType.CVE:
            return result

        cve_id = ioc.value.upper()
        row = self._cache.get(cve_id)
        if row is None:
            data = self.get(self.BASE_URL, params={"cve": cve_id})
            rows = data.get("data") if data else None
            row = allowlisted_object(rows[0], {"cve", "epss", "percentile"}) if isinstance(rows, list) and rows else None
            if row and api_cve(row.get("cve")) != cve_id:
                row = None
            if row and api_probability(row.get("epss")) is None:
                row = None
            if row:
                self._cache[cve_id] = row

        if not row:
            result.errors[self.name] = "No EPSS data"
            return result

        result.epss_score = api_probability(row.get("epss"))
        result.epss_percentile = api_probability(row.get("percentile"))

        result.sources[self.name] = {
            "epss_score": result.epss_score,
            "percentile": result.epss_percentile,
        }
        return result
