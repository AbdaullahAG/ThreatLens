"""
Splunk Exporter — sends enrichment events to Splunk's HTTP Event Collector.
https://docs.splunk.com/Documentation/Splunk/latest/Data/HECRESTendpoint
"""

from __future__ import annotations

import json
from urllib.parse import urlsplit

from src.exporters.base import BaseExporter, ExportResult


class SplunkExporter(BaseExporter):
    name = "splunk"

    def __init__(self, hec_url: str, hec_token: str, index: str | None = None,
                 sourcetype: str = "threatlens", verify_tls: bool = True, **kwargs):
        host = urlsplit(hec_url.rstrip("/")).hostname
        super().__init__(allowed_hosts={host} if host else set(), verify_tls=verify_tls, **kwargs)
        self.hec_url = hec_url.rstrip("/")
        self.hec_token = hec_token
        self.index = index
        self.sourcetype = sourcetype

    def _secrets(self) -> tuple[str, ...]:
        return (self.hec_token,)

    def send_batch(self, events: list[dict]) -> ExportResult:
        endpoint = f"{self.hec_url}/services/collector/event"
        headers = {
            "Authorization": f"Splunk {self.hec_token}",
            "Content-Type": "application/json",
        }

        sent = 0
        failed = 0
        for batch in self.chunk(events, self.batch_size):
            # Splunk HEC accepts a stream of concatenated JSON event objects
            # (not a JSON array) in a single POST body.
            body = "\n".join(
                json.dumps(
                    {
                        "event": event,
                        "sourcetype": self.sourcetype,
                        **({"index": self.index} if self.index else {}),
                    },
                    default=str,
                )
                for event in batch
            )
            response = self._post(endpoint, data=body, headers=headers)
            if response is not None:
                sent += len(batch)
            else:
                failed += len(batch)

        return ExportResult(
            exporter=self.name,
            success=failed == 0,
            sent=sent,
            failed=failed,
            error=None if failed == 0 else f"{failed} event(s) failed to reach Splunk HEC",
        )
