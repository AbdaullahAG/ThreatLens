"""
Base Enricher — abstract base class for all API enrichers.
"""

import time
import logging
import requests
from abc import ABC, abstractmethod
from typing import Optional

from src.models import IOC, EnrichmentResult


class BaseEnricher(ABC):
    """
    All API enrichers inherit from this class.
    Provides shared HTTP session, timeout, delay, and retry logic.
    """

    name: str = "base"
    supports: list = []  # List of IOCType this enricher handles

    def __init__(self, api_key: Optional[str], timeout: int = 10, delay: float = 0.5):
        self.api_key = api_key
        self.timeout = timeout
        self.delay = delay
        self.logger = logging.getLogger(f"threatlens.{self.name}")
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "ThreatLens/2.0"})

    def is_available(self) -> bool:
        """Return True if this enricher has a valid API key (or doesn't need one)."""
        return True

    @abstractmethod
    def enrich(self, ioc: IOC, result: EnrichmentResult) -> EnrichmentResult:
        """
        Enrich the result object in-place and return it.
        Should catch all exceptions internally and log them.
        """
        ...

    def get(self, url: str, params: dict = None, headers: dict = None) -> Optional[dict]:
        """Perform a GET request with error handling."""
        try:
            resp = self.session.get(
                url,
                params=params,
                headers=headers,
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 429:
                self.logger.warning(f"[{self.name}] Rate limit hit — sleeping 60s")
                time.sleep(60)
                return None
            elif resp.status_code == 401:
                self.logger.error(f"[{self.name}] Invalid API key")
                return None
            elif resp.status_code == 404:
                self.logger.debug(f"[{self.name}] 404 — IOC not found in database")
                return None
            else:
                self.logger.warning(
                    f"[{self.name}] HTTP {resp.status_code} for {url}"
                )
                return None
        except requests.exceptions.Timeout:
            self.logger.warning(f"[{self.name}] Request timed out: {url}")
            return None
        except requests.exceptions.ConnectionError as e:
            self.logger.warning(f"[{self.name}] Connection error: {e}")
            return None
        except Exception as e:
            self.logger.error(f"[{self.name}] Unexpected error: {e}")
            return None
        finally:
            time.sleep(self.delay)
