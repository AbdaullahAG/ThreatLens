"""Local, parameterised SQLite persistence for cache entries and investigations."""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

from src.models import AssetRecord, EnrichmentResult, IOC
from src.utils.security import validate_ioc

MAX_WATCHLIST_ENTRIES = 10_000
MAX_WATCHLIST_OBSERVATIONS = 100_000


class InvestigationStore:
    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as conn:
            cache_columns = {
                row["name"]
                for row in conn.execute("PRAGMA table_info(enrichment_cache)").fetchall()
            }
            if not cache_columns:
                conn.execute(
                    """CREATE TABLE enrichment_cache (
                        ioc_type TEXT NOT NULL,
                        ioc_value TEXT NOT NULL,
                        provider_scope TEXT NOT NULL,
                        expires_at INTEGER NOT NULL,
                        payload TEXT NOT NULL,
                        PRIMARY KEY (ioc_type, ioc_value, provider_scope)
                    )"""
                )
            elif "provider_scope" not in cache_columns:
                # Preserve old entries for forensic/manual inspection, but mark
                # them unscoped so they cannot satisfy a scoped cache lookup.
                conn.execute("ALTER TABLE enrichment_cache RENAME TO enrichment_cache_legacy")
                conn.execute(
                    """CREATE TABLE enrichment_cache (
                        ioc_type TEXT NOT NULL,
                        ioc_value TEXT NOT NULL,
                        provider_scope TEXT NOT NULL,
                        expires_at INTEGER NOT NULL,
                        payload TEXT NOT NULL,
                        PRIMARY KEY (ioc_type, ioc_value, provider_scope)
                    )"""
                )
                conn.execute(
                    """INSERT INTO enrichment_cache
                       (ioc_type, ioc_value, provider_scope, expires_at, payload)
                       SELECT ioc_type, ioc_value, 'legacy-unscoped', expires_at, payload
                       FROM enrichment_cache_legacy"""
                )
                conn.execute("DROP TABLE enrichment_cache_legacy")

            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS investigations (
                    id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    total_iocs INTEGER NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS feed_cache (
                    feed_name TEXT PRIMARY KEY,
                    fetched_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS assets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hostname TEXT,
                    ip_address TEXT,
                    criticality TEXT NOT NULL,
                    internet_facing INTEGER NOT NULL DEFAULT 0,
                    owner TEXT,
                    product TEXT,
                    imported_at TEXT NOT NULL,
                    source_file TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_assets_hostname ON assets (hostname);
                CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets (ip_address);
                CREATE TABLE IF NOT EXISTS watchlist (
                    ioc_type TEXT NOT NULL,
                    ioc_value TEXT NOT NULL,
                    added_at TEXT NOT NULL,
                    expires_at INTEGER,
                    PRIMARY KEY (ioc_type, ioc_value)
                );
                CREATE TABLE IF NOT EXISTS watchlist_observations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ioc_type TEXT NOT NULL,
                    ioc_value TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    snapshot TEXT NOT NULL,
                    changed_fields TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_watchlist_observations_latest
                    ON watchlist_observations (ioc_type, ioc_value, id DESC);
                """
            )

    def get_cached(
        self, ioc: IOC, now: int, provider_scope: str = "all"
    ) -> Optional[EnrichmentResult]:
        with self._connect() as conn:
            row = conn.execute(
                """SELECT payload FROM enrichment_cache
                   WHERE ioc_type = ? AND ioc_value = ? AND provider_scope = ? AND expires_at > ?""",
                (ioc.ioc_type.value, ioc.value, provider_scope, now),
            ).fetchone()
        return EnrichmentResult.from_dict(json.loads(row["payload"])) if row else None

    def get_cached_any_scope(self, ioc: IOC, now: int) -> Optional[EnrichmentResult]:
        """Return the freshest valid scoped result for an offline lookup."""
        with self._connect() as conn:
            row = conn.execute(
                """SELECT payload FROM enrichment_cache
                   WHERE ioc_type = ? AND ioc_value = ? AND provider_scope != 'legacy-unscoped'
                     AND expires_at > ?
                   ORDER BY expires_at DESC LIMIT 1""",
                (ioc.ioc_type.value, ioc.value, now),
            ).fetchone()
        return EnrichmentResult.from_dict(json.loads(row["payload"])) if row else None

    def cache_result(
        self,
        result: EnrichmentResult,
        expires_at: int,
        provider_scope: str = "all",
    ) -> None:
        payload = json.dumps(result.to_dict(), sort_keys=True, default=str)
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO enrichment_cache
                   (ioc_type, ioc_value, provider_scope, expires_at, payload)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(ioc_type, ioc_value, provider_scope) DO UPDATE SET
                     expires_at = excluded.expires_at, payload = excluded.payload""",
                (result.ioc.ioc_type.value, result.ioc.value, provider_scope, expires_at, payload),
            )

    # ------------------------------------------------------------------
    # Generic feed cache (e.g. CISA KEV bulk feed)
    # ------------------------------------------------------------------

    def get_cached_feed(self, feed_name: str, now: int) -> Optional[dict]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT payload FROM feed_cache WHERE feed_name = ? AND expires_at > ?",
                (feed_name, now),
            ).fetchone()
        return json.loads(row["payload"]) if row else None

    def cache_feed(self, feed_name: str, payload: dict, now: int, expires_at: int) -> None:
        text = json.dumps(payload, default=str)
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO feed_cache (feed_name, fetched_at, expires_at, payload)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(feed_name) DO UPDATE SET
                     fetched_at = excluded.fetched_at,
                     expires_at = excluded.expires_at,
                     payload = excluded.payload""",
                (feed_name, now, expires_at, text),
            )

    # ------------------------------------------------------------------
    # Asset inventory
    # ------------------------------------------------------------------

    def replace_assets(self, assets: Iterable[AssetRecord], source_file: str) -> int:
        """Replace all previously imported assets with a freshly imported set."""
        imported_at = datetime.now(timezone.utc).isoformat()
        rows = [
            (
                asset.hostname,
                asset.ip_address,
                asset.criticality,
                1 if asset.internet_facing else 0,
                asset.owner,
                asset.product,
                imported_at,
                source_file,
            )
            for asset in assets
        ]
        with self._connect() as conn:
            conn.execute("DELETE FROM assets")
            conn.executemany(
                """INSERT INTO assets
                   (hostname, ip_address, criticality, internet_facing, owner, product, imported_at, source_file)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                rows,
            )
        return len(rows)

    def list_assets(self) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM assets").fetchall()
        return [dict(row) for row in rows]

    def record_investigation(self, results: Iterable[EnrichmentResult]) -> str:
        result_list = list(results)
        investigation_id = str(uuid.uuid4())
        created_at = datetime.now(timezone.utc).isoformat()
        payload = json.dumps([result.to_dict() for result in result_list], default=str)
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO investigations (id, created_at, total_iocs, payload) VALUES (?, ?, ?, ?)",
                (investigation_id, created_at, len(result_list), payload),
            )
        return investigation_id

    # ------------------------------------------------------------------
    # Local IOC watchlist and change timeline
    # ------------------------------------------------------------------

    def add_watchlist_iocs(self, iocs: Iterable[IOC], expires_at: Optional[int] = None) -> int:
        if expires_at is not None and (isinstance(expires_at, bool) or not isinstance(expires_at, int) or expires_at < 0):
            raise ValueError("watchlist expiry must be a non-negative Unix timestamp")
        added_at = datetime.now(timezone.utc).isoformat()
        rows = []
        for index, ioc in enumerate(iocs):
            if index >= MAX_WATCHLIST_ENTRIES:
                raise ValueError("watchlist entry limit exceeded")
            rows.append(
                (
                    ioc.ioc_type.value,
                    validate_ioc(ioc.value, ioc.ioc_type, allow_private=True),
                    added_at,
                    expires_at,
                )
            )
        with self._connect() as conn:
            existing = conn.execute("SELECT COUNT(*) FROM watchlist").fetchone()[0]
            new_keys = {(ioc_type, ioc_value) for ioc_type, ioc_value, _, _ in rows}
            already_present = sum(
                conn.execute(
                    "SELECT 1 FROM watchlist WHERE ioc_type = ? AND ioc_value = ?",
                    key,
                ).fetchone() is not None
                for key in new_keys
            )
            if existing + len(new_keys) - already_present > MAX_WATCHLIST_ENTRIES:
                raise ValueError("watchlist entry limit exceeded")
            conn.executemany(
                """INSERT INTO watchlist (ioc_type, ioc_value, added_at, expires_at)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(ioc_type, ioc_value) DO UPDATE SET
                     added_at = excluded.added_at,
                     expires_at = excluded.expires_at""",
                rows,
            )
        return len(rows)

    def list_watchlist(self, now: Optional[int] = None) -> list[dict]:
        now = int(datetime.now(timezone.utc).timestamp()) if now is None else now
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT ioc_type, ioc_value, added_at, expires_at
                   FROM watchlist WHERE expires_at IS NULL OR expires_at > ?
                   ORDER BY ioc_type, ioc_value""",
                (now,),
            ).fetchall()
        return [dict(row) for row in rows]

    def remove_watchlist_iocs(self, iocs: Iterable[IOC]) -> int:
        keys = [
            (ioc.ioc_type.value, validate_ioc(ioc.value, ioc.ioc_type, allow_private=True))
            for ioc in iocs
        ]
        removed = 0
        with self._connect() as conn:
            for ioc_type, ioc_value in keys:
                cursor = conn.execute(
                    "DELETE FROM watchlist WHERE ioc_type = ? AND ioc_value = ?",
                    (ioc_type, ioc_value),
                )
                removed += cursor.rowcount
        return removed

    @staticmethod
    def _watchlist_snapshot(result: EnrichmentResult) -> dict:
        return {
            "verdict": result.verdict,
            "confidence_score": result.confidence_score,
            "sources": sorted(result.sources),
            "abuse_score": result.abuse_score if result.ioc.ioc_type.value == "IP" else None,
            "malicious_votes": result.malicious_votes,
            "suspicious_votes": result.suspicious_votes,
            "positives": result.positives if result.ioc.ioc_type.value == "Hash" else None,
            "total_scanners": result.total_scanners if result.ioc.ioc_type.value == "Hash" else None,
            "cvss_score": result.cvss_score,
            "epss_score": result.epss_score,
            "cisa_kev": result.cisa_kev,
        }

    def record_watchlist_observation(
        self, result: EnrichmentResult, *, persist: bool = True
    ) -> Optional[dict]:
        validate_ioc(result.ioc.value, result.ioc.ioc_type, allow_private=True)
        now = datetime.now(timezone.utc)
        snapshot = self._watchlist_snapshot(result)
        with self._connect() as conn:
            active = conn.execute(
                """SELECT 1 FROM watchlist WHERE ioc_type = ? AND ioc_value = ?
                   AND (expires_at IS NULL OR expires_at > ?)""",
                (result.ioc.ioc_type.value, result.ioc.value, int(now.timestamp())),
            ).fetchone()
            if active is None:
                return None

            previous_row = conn.execute(
                """SELECT snapshot FROM watchlist_observations
                   WHERE ioc_type = ? AND ioc_value = ? ORDER BY id DESC LIMIT 1""",
                (result.ioc.ioc_type.value, result.ioc.value),
            ).fetchone()
            previous = json.loads(previous_row["snapshot"]) if previous_row else None
            if previous is None:
                changed_fields = ["baseline"]
            else:
                changed_fields = [
                    key for key, value in snapshot.items()
                    if previous.get(key) != value
                ]

            if persist:
                observation_count = conn.execute(
                    "SELECT COUNT(*) FROM watchlist_observations"
                ).fetchone()[0]
                if observation_count >= MAX_WATCHLIST_OBSERVATIONS:
                    raise ValueError("watchlist observation limit reached; export or archive the local database")
                conn.execute(
                    """INSERT INTO watchlist_observations
                       (ioc_type, ioc_value, observed_at, snapshot, changed_fields)
                       VALUES (?, ?, ?, ?, ?)""",
                    (
                        result.ioc.ioc_type.value,
                        result.ioc.value,
                        now.isoformat(),
                        json.dumps(snapshot, sort_keys=True),
                        json.dumps(changed_fields),
                    ),
                )

        return {
            "ioc": result.ioc,
            "observed_at": now.isoformat(),
            "changed_fields": changed_fields,
            "is_baseline": previous is None,
        }
