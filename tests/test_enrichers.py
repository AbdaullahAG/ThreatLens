"""
Mock tests for BaseEnricher.get() — covers all HTTP edge-cases without
making real network requests.

Scenarios tested
─────────────────
1.  Redirect blocked          – 301 response → None (allow_redirects=False)
2.  Budget exhausted          – RequestBudget(0) → None immediately
3.  429 + Retry-After         – first 429, second 200 → returns payload
4.  429 + budget gone         – 429 then budget exhausted → None
5.  API key redacted in logs  – RequestException containing raw key → REDACTED
6.  Non-JSON content-type     – 200 + text/html → None
7.  Invalid JSON body         – 200 + application/json but json() raises → None
8.  Unapproved host blocked   – wrong hostname → None, no HTTP call made
9.  HTTP scheme blocked       – http:// URL → None, no HTTP call made
"""

from __future__ import annotations

import logging
from unittest.mock import MagicMock, patch

import requests

from src.enrichers.base import BaseEnricher
from src.models import IOC, IOCType, EnrichmentResult
from src.utils.quota import RequestBudget


# ── Minimal concrete subclass ─────────────────────────────────────────────────

class _TestEnricher(BaseEnricher):
    """Concrete subclass used only in tests — enrich() is a no-op."""

    name = "test"
    supports = [IOCType.IP]
    allowed_hosts = {"api.example.com"}

    def enrich(self, ioc: IOC, result: EnrichmentResult) -> EnrichmentResult:
        return result


APPROVED_URL = "https://api.example.com/v1/check"
BLOCKED_URL_WRONG_HOST = "https://api.evil.com/v1/check"
BLOCKED_URL_HTTP = "http://api.example.com/v1/check"

FAKE_KEY = "sk-SUPER-SECRET-0123456789"


def _make_enricher(api_key: str = FAKE_KEY, budget: RequestBudget | None = None) -> _TestEnricher:
    return _TestEnricher(api_key=api_key, timeout=5, delay=0.0, request_budget=budget)


def _mock_response(status: int, body: dict | None = None, content_type: str = "application/json", headers: dict | None = None) -> MagicMock:
    """Create a fake requests.Response."""
    resp = MagicMock()
    resp.status_code = status
    resp.headers = {"Content-Type": content_type, **(headers or {})}
    if body is not None:
        resp.json.return_value = body
    else:
        resp.json.side_effect = ValueError("No JSON")
    return resp


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestBaseEnricherGet:

    # 1. Redirect blocked (301 treated as non-200, non-known status)
    def test_redirect_blocked(self):
        enricher = _make_enricher()
        redirect_resp = _mock_response(301, headers={"Location": "https://api.example.com/other"})
        with patch.object(enricher.session, "get", return_value=redirect_resp) as mock_get:
            result = enricher.get(APPROVED_URL)
        # allow_redirects=False must be passed
        mock_get.assert_called_once()
        _, kwargs = mock_get.call_args
        assert kwargs.get("allow_redirects") is False
        assert result is None

    # 2. Budget exhausted before any request
    def test_budget_exhausted(self):
        budget = RequestBudget(maximum=0)
        enricher = _make_enricher(budget=budget)
        with patch.object(enricher.session, "get") as mock_get:
            result = enricher.get(APPROVED_URL)
        mock_get.assert_not_called()
        assert result is None

    # 3. 429 then 200 — returns payload; verifies Retry-After sleep
    def test_429_retry_after_success(self):
        enricher = _make_enricher()
        first_resp = _mock_response(429, headers={"Retry-After": "1"})
        second_resp = _mock_response(200, body={"data": "ok"})

        with patch.object(enricher.session, "get", side_effect=[first_resp, second_resp]):
            with patch("src.enrichers.base.time.sleep") as mock_sleep:
                result = enricher.get(APPROVED_URL)

        assert result == {"data": "ok"}
        # sleep called at least once with the Retry-After value
        sleep_args = [c.args[0] for c in mock_sleep.call_args_list]
        assert any(s >= 1 for s in sleep_args), f"Expected sleep ≥ 1s, got {sleep_args}"

    # 4. 429 then budget is exhausted on retry
    def test_429_retry_budget_exhausted(self):
        budget = RequestBudget(maximum=1)  # first call consumed; retry denied
        enricher = _make_enricher(budget=budget)
        first_resp = _mock_response(429, headers={"Retry-After": "1"})

        with patch.object(enricher.session, "get", return_value=first_resp):
            with patch("src.enrichers.base.time.sleep"):
                result = enricher.get(APPROVED_URL)

        assert result is None

    # 5. API key redacted in log when RequestException occurs
    def test_api_key_redacted_in_logs(self, caplog):
        enricher = _make_enricher(api_key=FAKE_KEY)
        exc = requests.RequestException(f"Connection failed: key={FAKE_KEY}")

        with patch.object(enricher.session, "get", side_effect=exc):
            with caplog.at_level(logging.WARNING, logger=f"threatlens.{enricher.name}"):
                result = enricher.get(APPROVED_URL)

        assert result is None
        # The raw API key must NOT appear in any log record
        for record in caplog.records:
            assert FAKE_KEY not in record.getMessage(), (
                f"Raw API key leaked into log: {record.getMessage()}"
            )
        # The REDACTED placeholder should appear instead
        assert any("[REDACTED]" in r.getMessage() for r in caplog.records)

    # 6. Non-JSON Content-Type → None
    def test_non_json_content_type(self):
        enricher = _make_enricher()
        resp = _mock_response(200, content_type="text/html; charset=utf-8")
        resp.json.return_value = {}  # should never be called

        with patch.object(enricher.session, "get", return_value=resp):
            result = enricher.get(APPROVED_URL)

        assert result is None

    # 7. application/json but body is not valid JSON
    def test_invalid_json_body(self):
        enricher = _make_enricher()
        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {"Content-Type": "application/json"}
        resp.json.side_effect = ValueError("No JSON object could be decoded")

        with patch.object(enricher.session, "get", return_value=resp):
            result = enricher.get(APPROVED_URL)

        assert result is None

    # 8. Unapproved host — no HTTP call made
    def test_unapproved_host_blocked(self):
        enricher = _make_enricher()
        with patch.object(enricher.session, "get") as mock_get:
            result = enricher.get(BLOCKED_URL_WRONG_HOST)
        mock_get.assert_not_called()
        assert result is None

    # 9. HTTP scheme blocked (only HTTPS allowed)
    def test_http_scheme_blocked(self):
        enricher = _make_enricher()
        with patch.object(enricher.session, "get") as mock_get:
            result = enricher.get(BLOCKED_URL_HTTP)
        mock_get.assert_not_called()
        assert result is None
