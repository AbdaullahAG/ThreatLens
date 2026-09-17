"""
Elastic Exporter — sends enrichment events to Elasticsearch via the
``_bulk`` API, authenticated with an API key (preferred over basic auth).
https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-bulk.html
"""

from __future__ import annotations

import json
from urllib.parse import urlsplit

from src.exporters.base import BaseExporter, ExportResult


class ElasticExporter(BaseExporter):
    name = "elastic"

    def __init__(self, elastic_url: str, api_key: str, index: str = "threatlens-iocs",
                 verify_tls: bool = True, **kwargs):
        host = urlsplit(elastic_url.rstrip("/")).hostname
        super().__init__(allowed_hosts={host} if host else set(), verify_tls=verify_tls, **kwargs)
        self.elastic_url = elastic_url.rstrip("/")
        self.api_key = api_key
        self.index = index

    def _secrets(self) -> tuple[str, ...]:
        return (self.api_key,)

    def send_batch(self, events: list[dict]) -> ExportResult:
        endpoint = f"{self.elastic_url}/_bulk"
        headers = {
            "Authorization": f"ApiKey {self.api_key}",
            "Content-Type": "application/x-ndjson",
        }

        sent = 0
        failed = 0
        for batch in self.chunk(events, self.batch_size):
            lines = []
            for event in batch:
                lines.append(json.dumps({"index": {"_index": self.index}}))
                lines.append(json.dumps(event, default=str))
            body = "\n".join(lines) + "\n"
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
            error=None if failed == 0 else f"{failed} event(s) failed to reach Elasticsearch",
        )
