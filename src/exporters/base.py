"""
Shared secure HTTP client for SIEM exporters (Splunk, Elastic, Sentinel).

Mirrors ``src.enrichers.base.BaseEnricher`` for outbound requests, but for
POSTing batches of events instead of GETting enrichment data:

* Every destination host must be on an explicit allow-list, computed from
  the *configured* endpoint (never from IOC/log content), which prevents
  SSRF if a destination URL were ever influenced by untrusted input.
* TLS certificate verification is always on unless the caller explicitly
  opts out (and doing so is logged loudly as a warning) — there is no
  silent ``verify=False``.
* Bounded retry with backoff; a single destination failing never raises
  out of ``send_batch`` — callers get a structured ``ExportResult`` so one
  broken SIEM integration can't take down the others.
* Secrets (tokens/keys) are never logged, even in error paths.
"""

from __future__ import annotations

import json
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Iterator, Optional

import requests

from src.utils.security import bounded_response_bytes, redact_secrets, validate_https_endpoint

MAX_EXPORT_RESPONSE_BYTES = 1 * 1024 * 1024
MAX_EXPORT_REQUEST_BYTES = 10 * 1024 * 1024


@dataclass
class ExportResult:
    exporter: str
    success: bool
    sent: int = 0
    failed: int = 0
    error: Optional[str] = None
    batches: list[dict] = field(default_factory=list)


class BaseExporter(ABC):
    name: str = "base"
    allowed_query_keys: set[str] = set()

    def __init__(
        self,
        allowed_hosts: set[str],
        allowed_authorities: set[tuple[str, int | None]] | None = None,
        timeout: int = 15,
        max_retries: int = 2,
        backoff_seconds: float = 1.0,
        verify_tls: bool = True,
        batch_size: int = 500,
    ):
        if not verify_tls:
            logging.getLogger(f"threatlens.export.{self.name}").warning(
                "[%s] TLS certificate verification is DISABLED for this destination — "
                "traffic can be intercepted or tampered with. Only use this for local testing.",
                self.name,
            )
        self.allowed_hosts = allowed_hosts
        self.allowed_authorities = allowed_authorities or {(host, None) for host in allowed_hosts}
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_seconds = backoff_seconds
        self.verify_tls = verify_tls
        self.batch_size = batch_size
        self.logger = logging.getLogger(f"threatlens.export.{self.name}")
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.headers.update({"User-Agent": "ThreatLens/2.2"})

    @abstractmethod
    def send_batch(self, events: list[dict]) -> ExportResult:
        """Send a batch of events to the destination, batching internally as needed."""

    def _secrets(self) -> tuple[str, ...]:
        """Subclasses override to list secret values that must never be logged."""
        return ()

    def _post(
        self,
        url: str,
        *,
        data: Any = None,
        json_body: Any = None,
        headers: Optional[dict] = None,
    ) -> Optional[bytes]:
        """POST bounded data to an allow-listed HTTPS host with capped retries."""
        if not validate_https_endpoint(
            url, self.allowed_hosts, allowed_query_keys=self.allowed_query_keys,
            allowed_authorities=self.allowed_authorities,
        ):
            self.logger.error("[%s] blocked POST to non-allow-listed destination", self.name)
            return None

        try:
            if data is not None:
                body_size = len(data if isinstance(data, bytes) else str(data).encode("utf-8"))
            elif json_body is not None:
                body_size = len(json.dumps(json_body, default=str).encode("utf-8"))
            else:
                body_size = 0
        except (TypeError, ValueError):
            self.logger.error("[%s] request body could not be serialized safely", self.name)
            return None
        if body_size > MAX_EXPORT_REQUEST_BYTES:
            self.logger.error("[%s] request body exceeds configured size limit", self.name)
            return None

        attempt = 0
        while True:
            try:
                response = self.session.post(
                    url,
                    data=data,
                    json=json_body,
                    headers=headers,
                    timeout=self.timeout,
                    verify=self.verify_tls,
                    allow_redirects=False,
                    stream=True,
                )
            except requests.RequestException as exc:
                self.logger.warning(
                    "[%s] request failed (attempt %d/%d): %s",
                    self.name, attempt + 1, self.max_retries + 1,
                    redact_secrets(exc, *self._secrets()),
                )
                response = None

            if response is not None and response.status_code < 300:
                body = bounded_response_bytes(response, MAX_EXPORT_RESPONSE_BYTES)
                if body is None:
                    self.logger.warning("[%s] destination response exceeded size limit", self.name)
                return body
            if response is not None and response.status_code not in (429, 500, 502, 503, 504):
                self.logger.warning(
                    "[%s] destination returned HTTP %s", self.name, response.status_code
                )
                response.close()
                return None
            if response is not None:
                response.close()

            attempt += 1
            if attempt > self.max_retries:
                self.logger.error("[%s] giving up after %d attempts", self.name, attempt)
                return None
            time.sleep(self.backoff_seconds * (2 ** (attempt - 1)))

    @staticmethod
    def chunk(items: list[Any], size: int) -> Iterator[list[Any]]:
        for start in range(0, len(items), size):
            yield items[start:start + size]
