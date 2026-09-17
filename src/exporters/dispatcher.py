"""
Export Dispatcher — builds whichever SIEM exporters have complete
configuration and sends a batch of events to each independently, so one
misconfigured or unreachable SIEM never blocks delivery to the others.
"""

from __future__ import annotations

import logging
from typing import Optional

from src.exporters.base import ExportResult
from src.exporters.elastic import ElasticExporter
from src.exporters.sentinel import SentinelExporter
from src.exporters.splunk import SplunkExporter
from src.models import EnrichmentResult
from src.utils.config import Config

logger = logging.getLogger("threatlens.exporters")


def build_exporters(config: Config, selected: Optional[list[str]] = None, verify_tls: bool = True) -> list:
    available = config.configured_exporters()
    exporters = []

    def wanted(name: str) -> bool:
        return available.get(name, False) and (not selected or name in selected)

    if wanted("splunk"):
        exporters.append(
            SplunkExporter(
                hec_url=config.splunk_hec_url,
                hec_token=config.splunk_hec_token,
                index=config.splunk_index,
                verify_tls=verify_tls,
            )
        )
    if wanted("elastic"):
        exporters.append(
            ElasticExporter(
                elastic_url=config.elastic_url,
                api_key=config.elastic_api_key,
                index=config.elastic_index,
                verify_tls=verify_tls,
            )
        )
    if wanted("sentinel"):
        exporters.append(
            SentinelExporter(
                tenant_id=config.sentinel_tenant_id,
                client_id=config.sentinel_client_id,
                client_secret=config.sentinel_client_secret,
                dce_endpoint=config.sentinel_dce_endpoint,
                dcr_immutable_id=config.sentinel_dcr_immutable_id,
                stream_name=config.sentinel_stream_name,
                verify_tls=verify_tls,
            )
        )
    return exporters


def results_to_events(results: list[EnrichmentResult]) -> list[dict]:
    return [result.to_dict() for result in results]


def export_results(exporters: list, results: list[EnrichmentResult]) -> list[ExportResult]:
    """Send results to every configured exporter, isolating failures per destination."""
    events = results_to_events(results)
    outcomes: list[ExportResult] = []
    for exporter in exporters:
        try:
            outcomes.append(exporter.send_batch(events))
        except Exception as exc:  # noqa: BLE001 - one destination failing must not abort the run
            logger.error("[%s] exporter crashed: %s", getattr(exporter, "name", "unknown"), exc)
            outcomes.append(
                ExportResult(exporter=getattr(exporter, "name", "unknown"), success=False, failed=len(events), error=str(exc))
            )
    return outcomes
