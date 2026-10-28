"""Local, parameterised SQLite persistence for cache entries and investigations."""

from __future__ import annotations

import json
import re
import sqlite3
import uuid
from datetime import date, datetime, time as datetime_time, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

from src.models import AssetRecord, EnrichmentResult, IOC, IOCType
from src.utils.security import validate_ioc

MAX_WATCHLIST_ENTRIES = 10_000
MAX_WATCHLIST_OBSERVATIONS = 100_000
MAX_HISTORY_QUERY_LIMIT = 500
MAX_HISTORY_QUERY_LENGTH = 256
MAX_HISTORY_INDEX_ROWS = 100_000


class InvestigationStore:
    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
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
                CREATE TABLE IF NOT EXISTS investigation_items (
                    investigation_id TEXT NOT NULL,
                    result_index INTEGER NOT NULL,
                    ioc_type TEXT NOT NULL,
                    ioc_value TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    severity TEXT,
                    confidence_score INTEGER NOT NULL DEFAULT 0,
                    sources_json TEXT NOT NULL,
                    PRIMARY KEY (investigation_id, result_index),
                    FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_investigation_items_ioc
                    ON investigation_items (ioc_type, ioc_value, investigation_id);
                CREATE INDEX IF NOT EXISTS idx_investigation_items_verdict
                    ON investigation_items (verdict, severity, investigation_id);
                CREATE TABLE IF NOT EXISTS application_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
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
            self._backfill_investigation_index(conn)

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
            conn.executemany(
                """INSERT INTO investigation_items
                   (investigation_id, result_index, ioc_type, ioc_value, verdict,
                    severity, confidence_score, sources_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    (
                        investigation_id,
                        index,
                        result.ioc.ioc_type.value,
                        validate_ioc(result.ioc.value, result.ioc.ioc_type, allow_private=True),
                        result.verdict,
                        result.severity,
                        result.confidence_score,
                        json.dumps(sorted(result.sources.keys()), ensure_ascii=True),
                    )
                    for index, result in enumerate(result_list)
                ],
            )
        return investigation_id

    @staticmethod
    def _backfill_investigation_index(conn: sqlite3.Connection) -> None:
        """Index existing history once so older investigations remain searchable."""
        marker = conn.execute(
            "SELECT value FROM application_metadata WHERE key = ?",
            ("investigation_items_backfilled_v1",),
        ).fetchone()
        if marker:
            return

        rows = conn.execute(
            "SELECT id, payload FROM investigations ORDER BY created_at DESC LIMIT ?",
            (MAX_HISTORY_INDEX_ROWS,),
        ).fetchall()
        scanned = 0
        remaining = MAX_HISTORY_INDEX_ROWS
        for row in rows:
            if remaining <= 0:
                break
            if len(row["payload"]) > 25 * 1024 * 1024:
                continue
            try:
                results = json.loads(row["payload"])
            except (TypeError, json.JSONDecodeError):
                continue
            if not isinstance(results, list):
                continue
            for index, result in enumerate(results):
                if scanned >= MAX_HISTORY_INDEX_ROWS:
                    break
                scanned += 1
                if not isinstance(result, dict):
                    continue
                ioc = result.get("ioc")
                if not isinstance(ioc, dict):
                    continue
                ioc_type = ioc.get("type")
                ioc_value = ioc.get("value")
                # Legacy payloads use the stable enum value in `ioc.type`.
                try:
                    parsed_type = IOCType(ioc_type)
                    canonical_value = validate_ioc(str(ioc_value), parsed_type, allow_private=True)
                except (ValueError, TypeError):
                    continue
                sources = result.get("sources", {})
                source_names = sorted(sources.keys()) if isinstance(sources, dict) else []
                try:
                    confidence = max(0, min(100, int(result.get("confidence_score", 0))))
                except (TypeError, ValueError):
                    confidence = 0
                conn.execute(
                    """INSERT OR IGNORE INTO investigation_items
                       (investigation_id, result_index, ioc_type, ioc_value, verdict,
                        severity, confidence_score, sources_json)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        row["id"], index, parsed_type.value, canonical_value,
                        str(result.get("verdict", "Unknown"))[:32],
                        str(result.get("severity"))[:64] if result.get("severity") is not None else None,
                        confidence, json.dumps(source_names[:100], ensure_ascii=True),
                    ),
                )
                remaining -= 1
        conn.execute(
            "INSERT OR REPLACE INTO application_metadata (key, value) VALUES (?, ?)",
            (
                "investigation_items_backfilled_v1",
                "limited" if remaining <= 0 or scanned >= MAX_HISTORY_INDEX_ROWS
                or len(rows) >= MAX_HISTORY_INDEX_ROWS else "complete",
            ),
        )

    def history_index_limited(self) -> bool:
        """Report whether legacy backfill stopped at its safety cap."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT value FROM application_metadata WHERE key = ?",
                ("investigation_items_backfilled_v1",),
            ).fetchone()
        return bool(row and row["value"] == "limited")

    @staticmethod
    def _validate_history_datetime(value: Optional[str], field_name: str) -> Optional[str]:
        """Validate and normalize a date or ISO-8601 timestamp for history queries."""
        if value is None:
            return None
        if not isinstance(value, str) or len(value) > 64:
            raise ValueError(f"{field_name} must be an ISO date or timestamp")
        try:
            if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
                boundary = datetime.max.time() if field_name == "history end" else datetime_time.min
                return datetime.combine(date.fromisoformat(value), boundary, tzinfo=timezone.utc).isoformat()
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"{field_name} must be an ISO date or timestamp") from exc
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat()

    @staticmethod
    def _escape_like(value: str) -> str:
        return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

    def search_history(
        self,
        query: Optional[str] = None,
        *,
        exact_ioc: Optional[IOC] = None,
        ioc_type: Optional[str] = None,
        verdict: Optional[str] = None,
        severity: Optional[str] = None,
        since: Optional[str] = None,
        until: Optional[str] = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Search local IOC observations with bounded, parameterized filters."""
        if query is not None and (
            not query.strip()
            or len(query) > MAX_HISTORY_QUERY_LENGTH
            or any(ord(char) < 32 for char in query)
        ):
            raise ValueError(f"history query must be 1-{MAX_HISTORY_QUERY_LENGTH} characters")
        if exact_ioc is not None:
            exact_value = validate_ioc(exact_ioc.value, exact_ioc.ioc_type, allow_private=True)
        else:
            exact_value = None
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_HISTORY_QUERY_LIMIT:
            raise ValueError(f"history limit must be between 1 and {MAX_HISTORY_QUERY_LIMIT}")
        if ioc_type is not None and ioc_type not in {item.value for item in IOCType}:
            raise ValueError("unsupported IOC type filter")
        if verdict is not None and verdict not in {
            "Malicious", "Suspicious", "Clean", "Unknown", "Critical", "High", "Medium", "Low"
        }:
            raise ValueError("unsupported verdict filter")
        if severity is not None and severity.upper() not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
            raise ValueError("unsupported severity filter")

        start = self._validate_history_datetime(since, "history start")
        end = self._validate_history_datetime(until, "history end")
        if start and end and start > end:
            raise ValueError("history start must not be after history end")

        query_needle = f"%{self._escape_like(query.strip())}%" if query is not None else None
        exact_type = exact_ioc.ioc_type.value if exact_ioc is not None else None
        sql = """SELECT inv.id, inv.created_at, inv.payload, ii.result_index, ii.ioc_type,
                        ii.ioc_value, ii.verdict, ii.severity, ii.confidence_score, ii.sources_json
                 FROM investigation_items AS ii JOIN investigations AS inv
                   ON inv.id = ii.investigation_id
                 WHERE (? OR (ii.ioc_value LIKE ? ESCAPE '\\' COLLATE NOCASE
                              OR ii.sources_json LIKE ? ESCAPE '\\' COLLATE NOCASE))
                   AND (? OR (ii.ioc_type = ? AND ii.ioc_value = ? COLLATE NOCASE))
                   AND (? OR ii.ioc_type = ?)
                   AND (? OR ii.verdict = ?)
                   AND (? OR UPPER(COALESCE(ii.severity, '')) = ?)
                   AND (? OR inv.created_at >= ?)
                   AND (? OR inv.created_at <= ?)
                 ORDER BY inv.created_at DESC, ii.result_index ASC LIMIT ?"""
        parameters = (
            query is None, query_needle, query_needle,
            exact_value is None, exact_type, exact_value,
            ioc_type is None, ioc_type,
            verdict is None, verdict,
            severity is None, severity.upper() if severity else None,
            start is None, start,
            end is None, end,
            limit + 1,
        )
        with self._connect() as conn:
            rows = conn.execute(sql, parameters).fetchall()
        return self._history_rows(rows, limit)

    @staticmethod
    def _history_rows(rows: list[sqlite3.Row], limit: int) -> list[dict[str, Any]]:
        """Materialize indexed metadata and the corresponding stored result."""
        output: list[dict[str, Any]] = []
        payload_cache: dict[str, Any] = {}
        for row in rows[:limit]:
            result: dict[str, Any] = {}
            try:
                investigation_id = row["id"]
                if investigation_id not in payload_cache:
                    raw_payload = row["payload"]
                    if len(raw_payload) > 25 * 1024 * 1024:
                        payload_cache[investigation_id] = []
                    else:
                        payload_cache[investigation_id] = json.loads(raw_payload)
                payload = payload_cache[investigation_id]
                candidate = payload[row["result_index"]]
                if isinstance(candidate, dict):
                    result = candidate
            except (TypeError, ValueError, IndexError, KeyError, json.JSONDecodeError):
                pass
            try:
                sources = json.loads(row["sources_json"])
            except (TypeError, json.JSONDecodeError):
                sources = []
            output.append({
                "investigation_id": row["id"],
                "created_at": row["created_at"],
                "ioc_type": row["ioc_type"],
                "ioc_value": row["ioc_value"],
                "verdict": row["verdict"],
                "severity": row["severity"],
                "confidence_score": row["confidence_score"],
                "sources": sources if isinstance(sources, list) else [],
                "result": result,
            })
        return output

    def ioc_history(self, ioc: IOC, *, limit: int = 50) -> list[dict[str, Any]]:
        """Return the saved timeline for one validated IOC."""
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_HISTORY_QUERY_LIMIT:
            raise ValueError(f"history limit must be between 1 and {MAX_HISTORY_QUERY_LIMIT}")
        return self.search_history(
            exact_ioc=ioc, limit=min(limit, MAX_HISTORY_QUERY_LIMIT)
        )[:limit]

    def related_iocs(self, ioc: IOC, *, limit: int = 20) -> list[dict[str, Any]]:
        """Return IOCs previously recorded in the same investigations as an IOC."""
        value = validate_ioc(ioc.value, ioc.ioc_type, allow_private=True)
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ValueError("related IOC limit must be between 1 and 100")
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT related.ioc_type, related.ioc_value,
                          COUNT(DISTINCT related.investigation_id) AS shared_investigations,
                          MAX(inv.created_at) AS last_seen
                   FROM investigation_items AS target
                   JOIN investigation_items AS related
                     ON related.investigation_id = target.investigation_id
                   JOIN investigations AS inv ON inv.id = related.investigation_id
                   WHERE target.ioc_type = ? AND target.ioc_value = ?
                     AND (related.ioc_type != target.ioc_type OR related.ioc_value != target.ioc_value)
                   GROUP BY related.ioc_type, related.ioc_value
                   ORDER BY shared_investigations DESC, last_seen DESC
                   LIMIT ?""",
                (ioc.ioc_type.value, value, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def delete_investigation(self, investigation_id: str) -> bool:
        """Delete one investigation and its indexed rows by its exact UUID."""
        try:
            canonical_id = str(uuid.UUID(investigation_id))
        except (ValueError, TypeError, AttributeError) as exc:
            raise ValueError("investigation id must be a UUID") from exc
        with self._connect() as conn:
            cursor = conn.execute("DELETE FROM investigations WHERE id = ?", (canonical_id,))
        return cursor.rowcount > 0

    def prune_investigations(self, older_than: str) -> int:
        """Delete investigations older than a validated ISO timestamp."""
        cutoff = self._validate_history_datetime(older_than, "retention cutoff")
        if cutoff is None:
            raise ValueError("retention cutoff is required")
        with self._connect() as conn:
            cursor = conn.execute("DELETE FROM investigations WHERE created_at < ?", (cutoff,))
        return cursor.rowcount

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
