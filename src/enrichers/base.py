"""Shared safe HTTP client for intelligence providers."""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from typing import Optional
from urllib.parse import urlsplit

import requests

from src.models import EnrichmentResult, IOC
from src.utils.quota import RequestBudget
from src.utils.security import redact_secrets


class BaseEnricher(ABC):
    name: str = "base"
    supports: list = []
    allowed_hosts: set[str] = set()

    def __init__(
        self,
        api_key: Optional[str],
        timeout: int = 10,
        delay: float = 0.5,
        request_budget: Optional[RequestBudget] = None,
    ):
        self.api_key = api_key
        self.timeout = timeout
        self.delay = delay
        self.request_budget = request_budget
        self.logger = logging.getLogger(f"threatlens.{self.name}")
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "ThreatLens/2.1"})

    def is_available(self) -> bool:
        return True

    @abstractmethod
    def enrich(self, ioc: IOC, result: EnrichmentResult) -> EnrichmentResult:
        """Enrich ``result`` without propagating provider errors."""

    def get(self, url: str, params: dict = None, headers: dict = None) -> Optional[dict]:
        """GET only an approved HTTPS host with a bounded retry and budget."""
        parsed = urlsplit(url)
        if parsed.scheme != "https" or parsed.hostname not in self.allowed_hosts:
            self.logger.error("[%s] blocked unexpected provider endpoint", self.name)
            return None
        if self.request_budget and not self.request_budget.acquire(self.name):
            self.logger.warning("[%s] request budget exhausted", self.name)
            return None
        try:
            response = self.session.get(url, params=params, headers=headers, timeout=self.timeout, allow_redirects=False)
            if response.status_code == 429:
                return self._retry_once(url, params, headers, response)
            if response.status_code == 401:
                self.logger.error("[%s] API key rejected", self.name)
                return None
            if response.status_code == 404:
                self.logger.debug("[%s] IOC not found", self.name)
                return None
            if response.status_code != 200:
                self.logger.warning("[%s] provider returned HTTP %s", self.name, response.status_code)
                return None
            return self._json_payload(response)
        except requests.exceptions.Timeout:
            self.logger.warning("[%s] request timed out", self.name)
            return None
        except requests.RequestException as exc:
            self.logger.warning("[%s] request failed: %s", self.name, redact_secrets(exc, self.api_key))
            return None
        except ValueError as exc:
            self.logger.warning("[%s] invalid JSON response: %s", self.name, redact_secrets(exc, self.api_key))
            return None
        finally:
            if self.delay:
                time.sleep(self.delay)

    def _retry_once(self, url: str, params: dict | None, headers: dict | None, response) -> Optional[dict]:
        try:
            seconds = min(max(int(response.headers.get("Retry-After", "1")), 1), 15)
        except ValueError:
            seconds = 1
        self.logger.warning("[%s] rate limited; retrying once in %ss", self.name, seconds)
        time.sleep(seconds)
        if self.request_budget and not self.request_budget.acquire(self.name):
            return None
        retry = self.session.get(url, params=params, headers=headers, timeout=self.timeout, allow_redirects=False)
        return self._json_payload(retry) if retry.status_code == 200 else None

    def _json_payload(self, response) -> Optional[dict]:
        if "json" not in response.headers.get("Content-Type", "").lower():
            self.logger.warning("[%s] provider returned a non-JSON response", self.name)
            return None
        payload = response.json()
        return payload if isinstance(payload, dict) else None
