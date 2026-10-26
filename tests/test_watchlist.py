"""Tests for bounded, parameterized, local-only IOC watchlist persistence."""

from __future__ import annotations

import sqlite3
import time

import pytest

from src.models import EnrichmentResult, IOC, IOCType
from src.storage import InvestigationStore


def test_watchlist_add_expiry_remove_and_validation(tmp_path):
    store = InvestigationStore(str(tmp_path / "watchlist.db"))
    ioc = IOC("8.8.8.8", IOCType.IP)
    expiry = int(time.time()) + 120

    assert store.add_watchlist_iocs([ioc], expires_at=expiry) == 1
    assert store.list_watchlist()
    assert store.list_watchlist(now=expiry + 1) == []
    assert store.remove_watchlist_iocs([ioc]) == 1
    assert store.list_watchlist() == []

    with pytest.raises(ValueError, match="expiry"):
        store.add_watchlist_iocs([ioc], expires_at=True)
    with pytest.raises(ValueError):
        store.add_watchlist_iocs([IOC("not-an-ip", IOCType.IP)])


def test_watchlist_observations_report_changes_and_no_history_does_not_persist(tmp_path):
    db_path = tmp_path / "watchlist.db"
    store = InvestigationStore(str(db_path))
    ioc = IOC("8.8.8.8", IOCType.IP)
    store.add_watchlist_iocs([ioc])

    baseline = store.record_watchlist_observation(EnrichmentResult(ioc=ioc))
    assert baseline["is_baseline"] is True
    changed = EnrichmentResult(ioc=ioc, verdict="Malicious", confidence_score=90, abuse_score=90)
    update = store.record_watchlist_observation(changed)
    assert update["changed_fields"]
    assert "verdict" in update["changed_fields"]

    transient = store.record_watchlist_observation(
        EnrichmentResult(ioc=ioc, verdict="Unknown"), persist=False
    )
    assert transient["changed_fields"]
    with sqlite3.connect(db_path) as connection:
        count = connection.execute("SELECT COUNT(*) FROM watchlist_observations").fetchone()[0]
    assert count == 2


def test_watchlist_values_are_bound_sql_parameters(tmp_path):
    store = InvestigationStore(str(tmp_path / "watchlist.db"))
    ioc = IOC("https://example.com/path%27%20OR%201%3D1", IOCType.URL)
    store.add_watchlist_iocs([ioc])
    entries = store.list_watchlist()
    assert len(entries) == 1
    assert entries[0]["ioc_value"] == ioc.value
