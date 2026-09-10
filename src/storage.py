"""Local, parameterised SQLite persistence for cache entries and investigations."""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

from src.models import EnrichmentResult, IOC


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
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS enrichment_cache (
                    ioc_type TEXT NOT NULL,
                    ioc_value TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    payload TEXT NOT NULL,
                    PRIMARY KEY (ioc_type, ioc_value)
                );
                CREATE TABLE IF NOT EXISTS investigations (
                    id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    total_iocs INTEGER NOT NULL,
                    payload TEXT NOT NULL
                );
                """
            )

    def get_cached(self, ioc: IOC, now: int) -> Optional[EnrichmentResult]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT payload FROM enrichment_cache WHERE ioc_type = ? AND ioc_value = ? AND expires_at > ?",
                (ioc.ioc_type.value, ioc.value, now),
            ).fetchone()
        return EnrichmentResult.from_dict(json.loads(row["payload"])) if row else None

    def cache_result(self, result: EnrichmentResult, expires_at: int) -> None:
        payload = json.dumps(result.to_dict(), sort_keys=True, default=str)
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO enrichment_cache (ioc_type, ioc_value, expires_at, payload)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(ioc_type, ioc_value) DO UPDATE SET
                     expires_at = excluded.expires_at, payload = excluded.payload""",
                (result.ioc.ioc_type.value, result.ioc.value, expires_at, payload),
            )

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
