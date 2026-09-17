"""
Enricher Registry — maps IOC types to their enrichers and dispatches calls.
"""

import logging
from typing import Optional

from src.models import IOC, EnrichmentResult
from src.utils.config import Config
from src.enrichers.abuseipdb import AbuseIPDBEnricher
from src.enrichers.virustotal import VirusTotalEnricher
from src.enrichers.otx import OTXEnricher
from src.enrichers.shodan import ShodanEnricher
from src.enrichers.urlscan import URLScanEnricher
from src.enrichers.nvd import NVDEnricher
from src.enrichers.cisa_kev import CISAKEVEnricher
from src.enrichers.epss import EPSSEnricher
from src.utils.quota import RequestBudget

logger = logging.getLogger("threatlens.registry")

# Ordered list of all enricher classes
ALL_ENRICHERS = [
    AbuseIPDBEnricher,
    VirusTotalEnricher,
    OTXEnricher,
    ShodanEnricher,
    URLScanEnricher,
    NVDEnricher,
    CISAKEVEnricher,
    EPSSEnricher,
]


def build_enrichers(
    config: Config,
    selected_apis: Optional[list[str]] = None,
    request_budget: Optional[RequestBudget] = None,
    store: Optional[object] = None,
) -> list:
    """
    Instantiate all enrichers that have keys configured.
    If selected_apis is provided, only those are returned.
    ``store`` is passed through to enrichers that cache bulk feeds locally
    (e.g. CISA KEV); enrichers that don't need it simply ignore it.
    """
    enrichers = []
    available = config.available_apis()

    for cls in ALL_ENRICHERS:
        api_name = cls.name
        # Filter by user selection
        if selected_apis and api_name not in selected_apis:
            continue
        # Check if API is available (key exists or free)
        if not available.get(api_name, False):
            logger.debug(f"Skipping {api_name} — no API key configured")
            continue

        instance = cls(
            api_key=config.get_key(api_name),
            timeout=config.timeout,
            delay=config.delay,
            request_budget=request_budget,
            store=store,
        )
        if api_name == "cisa_kev":
            instance.cache_ttl_seconds = config.kev_cache_ttl
        if instance.is_available():
            enrichers.append(instance)
            logger.debug(f"Registered enricher: {api_name}")

    return enrichers


def enrich_ioc(ioc: IOC, enrichers: list) -> EnrichmentResult:
    """
    Run all compatible enrichers against a single IOC.
    Returns a fully populated EnrichmentResult.
    """
    result = EnrichmentResult(ioc=ioc)

    compatible = [e for e in enrichers if ioc.ioc_type in e.supports]

    if not compatible:
        result.errors["registry"] = f"No enrichers support IOC type: {ioc.ioc_type}"
        return result

    for enricher in sorted(compatible, key=lambda item: item.name):
        try:
            logger.debug(f"  → {enricher.name}")
            result = enricher.enrich(ioc, result)
            result.set_verdict()
            if result.is_decisive():
                result.explanation.append("Further provider lookups were skipped after a decisive signal.")
                break
        except Exception as e:
            logger.error(f"Enricher {enricher.name} crashed: {e}")
            result.errors[enricher.name] = str(e)

    # Derive final verdict after all enrichers have run
    result.set_verdict()
    return result
