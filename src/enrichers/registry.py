"""
Enricher Registry — maps IOC types to their enrichers and dispatches calls.
"""

import logging
from typing import Optional

from src.models import IOC, IOCType, EnrichmentResult
from src.utils.config import Config
from src.enrichers.abuseipdb import AbuseIPDBEnricher
from src.enrichers.virustotal import VirusTotalEnricher
from src.enrichers.otx import OTXEnricher
from src.enrichers.shodan import ShodanEnricher
from src.enrichers.urlscan import URLScanEnricher
from src.enrichers.nvd import NVDEnricher

logger = logging.getLogger("threatlens.registry")

# Ordered list of all enricher classes
ALL_ENRICHERS = [
    AbuseIPDBEnricher,
    VirusTotalEnricher,
    OTXEnricher,
    ShodanEnricher,
    URLScanEnricher,
    NVDEnricher,
]


def build_enrichers(
    config: Config,
    selected_apis: Optional[list[str]] = None,
) -> list:
    """
    Instantiate all enrichers that have keys configured.
    If selected_apis is provided, only those are returned.
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
        )
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

    for enricher in compatible:
        try:
            logger.debug(f"  → {enricher.name}")
            result = enricher.enrich(ioc, result)
        except Exception as e:
            logger.error(f"Enricher {enricher.name} crashed: {e}")
            result.errors[enricher.name] = str(e)

    # Derive final verdict after all enrichers have run
    result.set_verdict()
    return result
