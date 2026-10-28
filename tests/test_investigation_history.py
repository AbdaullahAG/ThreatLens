"""Tests for bounded local investigation search and lifecycle controls."""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from main import build_parser, validate_args
from src.engine import ThreatLensEngine
from src.models import EnrichmentResult, IOC, IOCType
from src.storage import InvestigationStore
from src.utils.config import Config


def _result(
    value: str = "198.51.100.10",
    ioc_type: IOCType = IOCType.IP,
    verdict: str = "Malicious",
    severity: str | None = None,
    sources: dict | None = None,
) -> EnrichmentResult:
    return EnrichmentResult(
        ioc=IOC(value, ioc_type),
        verdict=verdict,
        severity=severity,
        confidence_score=80,
        sources=sources or {"test_provider": {"status": "ok"}},
    )


def test_history_search_filters_type_verdict_source_and_date(tmp_path):
    store = InvestigationStore(str(tmp_path / "history.db"))
    store.record_investigation([_result(sources={"VirusTotal": {"status": "ok"}})])
    cve_id = store.record_investigation([
        _result("CVE-2024-12345", IOCType.CVE, "Critical", "CRITICAL", {"NVD": {"status": "ok"}})
    ])

    by_source = store.search_history("virustotal")
    by_type = store.search_history(ioc_type="CVE", verdict="Critical", severity="critical")
    by_date = store.search_history(since=datetime.now(timezone.utc).date().isoformat())

    assert len(by_source) == 1
    assert by_source[0]["sources"] == ["VirusTotal"]
    assert len(by_type) == 1
    assert by_type[0]["investigation_id"] == cve_id
    assert by_date


def test_history_query_treats_like_wildcards_as_literal_and_rejects_bounds(tmp_path):
    store = InvestigationStore(str(tmp_path / "history.db"))
    store.record_investigation([_result("198.51.100.10")])

    assert store.search_history("%") == []
    with pytest.raises(ValueError):
        store.search_history("x" * 257)
    with pytest.raises(ValueError):
        store.search_history(limit=501)
    with pytest.raises(ValueError):
        store.search_history(since="not-a-date")


def test_ioc_timeline_and_related_iocs_are_local_and_ordered(tmp_path):
    store = InvestigationStore(str(tmp_path / "history.db"))
    target = _result("198.51.100.10", verdict="Suspicious", sources={"OTX": {}})
    associated = _result("sample.example.com", IOCType.DOMAIN, "Malicious", sources={"VirusTotal": {}})
    first_id = store.record_investigation([target, associated])
    store.record_investigation([_result("198.51.100.10", verdict="Malicious", sources={"Shodan": {}})])

    timeline = store.ioc_history(IOC("198.51.100.10", IOCType.IP))
    related = store.related_iocs(IOC("198.51.100.10", IOCType.IP))

    assert [item["verdict"] for item in timeline] == ["Malicious", "Suspicious"]
    assert timeline[1]["investigation_id"] == first_id
    assert timeline[1]["sources"] == ["OTX"]
    assert related[0]["ioc_value"] == "sample.example.com"
    assert related[0]["shared_investigations"] == 1


def test_delete_and_retention_prune_remove_indexed_rows(tmp_path):
    store = InvestigationStore(str(tmp_path / "history.db"))
    old_id = store.record_investigation([_result()])
    recent_id = store.record_investigation([_result("203.0.113.9")])
    old_date = (datetime.now(timezone.utc) - timedelta(days=20)).isoformat()
    with sqlite3.connect(store.path) as connection:
        connection.execute("UPDATE investigations SET created_at = ? WHERE id = ?", (old_date, old_id))

    assert store.prune_investigations((datetime.now(timezone.utc) - timedelta(days=10)).isoformat()) == 1
    assert store.search_history(exact_ioc=IOC("198.51.100.10", IOCType.IP)) == []
    assert store.delete_investigation(recent_id)
    with pytest.raises(ValueError):
        store.delete_investigation("not-a-uuid")
    with sqlite3.connect(store.path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM investigation_items").fetchone()[0] == 0


def test_existing_investigation_rows_are_backfilled(tmp_path):
    db_path = tmp_path / "legacy.db"
    result = _result("legacy.example.com", IOCType.DOMAIN, "Suspicious", sources={"OTX": {}})
    legacy_payload = json.dumps([result.to_dict()])
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "CREATE TABLE investigations (id TEXT PRIMARY KEY, created_at TEXT NOT NULL, total_iocs INTEGER NOT NULL, payload TEXT NOT NULL)"
        )
        connection.execute(
            "INSERT INTO investigations VALUES (?, ?, ?, ?)",
            ("9a098565-2017-4e63-a2b9-c5f9562779ee", datetime.now(timezone.utc).isoformat(), 1, legacy_payload),
        )

    store = InvestigationStore(str(db_path))
    matches = store.search_history("legacy.example.com")

    assert len(matches) == 1
    assert matches[0]["verdict"] == "Suspicious"
    assert matches[0]["sources"] == ["OTX"]


def test_history_export_redacts_sensitive_values_and_does_not_overwrite(tmp_path):
    secret = "history-export-secret-value"
    env_path = tmp_path / "keys.env"
    env_path.write_text(f"VIRUSTOTAL_API_KEY={secret}\n", encoding="utf-8")
    db_path = tmp_path / "history.db"
    store = InvestigationStore(str(db_path))
    store.record_investigation([
        _result(sources={"VirusTotal": {"diagnostic": secret, "url": "https://example.com/?access_token=private"}})
    ])

    destination = tmp_path / "history-export.json"
    args = build_parser().parse_args([
        "--history-export", str(destination), "--cache-path", str(db_path), "--config", str(env_path)
    ])
    assert validate_args(args)
    engine = ThreatLensEngine(Config(config_path=str(env_path)), logging.getLogger("test"), args)

    assert engine.run()
    text = destination.read_text(encoding="utf-8")
    assert secret not in text
    assert "access_token=private" not in text
    assert "[REDACTED]" in text
    assert not engine.run()  # Exclusive create prevents replacing the first export.


def test_history_cli_options_are_standalone_and_bounded():
    parser = build_parser()
    search_args = parser.parse_args(["--history-search", "198.51.100.10", "--history-type", "IP"])
    assert validate_args(search_args)

    invalid_args = parser.parse_args(["--history-search", "foo", "--history-ioc", "IP:198.51.100.10"])
    assert not validate_args(invalid_args)

    over_limit = parser.parse_args(["--history-list", "--history-limit", "501"])
    assert not validate_args(over_limit)
