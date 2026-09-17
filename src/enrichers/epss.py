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

# FIRST.org accepts a comma-separated CVE list; keep batches modest to stay
# well under typical URL / query-string length limits.
_BATCH_SIZE = 100


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
        unique = sorted({cve.upper() for cve in cves if cve})
        for start in range(0, len(unique), _BATCH_SIZE):
            batch = unique[start:start + _BATCH_SIZE]
            data = self.get(self.BASE_URL, params={"cve": ",".join(batch)})
            if not data:
                continue
            for row in data.get("data", []):
                cve_id = str(row.get("cve", "")).upper()
                if cve_id:
                    self._cache[cve_id] = row

    def enrich(self, ioc: IOC, result: EnrichmentResult) -> EnrichmentResult:
        if ioc.ioc_type != IOCType.CVE:
            return result

        cve_id = ioc.value.upper()
        row = self._cache.get(cve_id)
        if row is None:
            data = self.get(self.BASE_URL, params={"cve": cve_id})
            rows = data.get("data") if data else None
            row = rows[0] if rows else None
            if row:
                self._cache[cve_id] = row

        if not row:
            result.errors[self.name] = "No EPSS data"
            return result

        try:
            result.epss_score = float(row.get("epss"))
        except (TypeError, ValueError):
            result.epss_score = None
        try:
            result.epss_percentile = float(row.get("percentile"))
        except (TypeError, ValueError):
            result.epss_percentile = None

        result.sources[self.name] = {
            "epss_score": result.epss_score,
            "percentile": result.epss_percentile,
        }
        return result
