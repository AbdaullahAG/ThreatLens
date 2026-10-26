"""Local, parameterised SQLite persistence for cache entries and investigations."""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

from src.models import AssetRecord, EnrichmentResult, IOC


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
