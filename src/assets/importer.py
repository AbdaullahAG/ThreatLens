"""
Asset Inventory Importer — safely loads a CSV of organizational assets
(hostname/IP, criticality, internet-facing, owner, product) for use in
CVE-to-asset correlation.

Security notes
---------------
* Uses ``csv.DictReader`` from the standard library only — no ``eval``,
  ``pickle``, or other dynamic execution of file content.
* Enforces a configurable maximum file size and row count to bound memory
  and processing time (DoS protection) — the file is streamed row by row,
  never loaded fully into memory as a single string.
* Every cell is passed through ``spreadsheet_value`` (the same Excel
  formula-injection neutralisation used elsewhere in the project) before
  being stored, since asset data can later be exported into report
  spreadsheets.
* Required columns are validated explicitly (allow-list of accepted
  header names); missing or duplicate required columns cause the whole
  import to be rejected rather than silently guessed at.
"""

from __future__ import annotations

import csv
import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from src.models import AssetRecord
from src.utils.security import has_control_characters, spreadsheet_value

# Accepted header names per logical column (case-insensitive).
_HOSTNAME_ALIASES = {"hostname", "host", "name"}
_IP_ALIASES = {"ip", "ip_address", "ipaddress"}
_CRITICALITY_ALIASES = {"criticality", "importance", "tier"}
_INTERNET_FACING_ALIASES = {"internet_facing", "internet-facing", "public", "external"}
_OWNER_ALIASES = {"owner", "team", "contact"}
_PRODUCT_ALIASES = {"product", "software", "application"}

_VALID_CRITICALITY = {"critical", "high", "medium", "low"}
_TRUE_VALUES = {"true", "yes", "y", "1", "internet", "public", "external"}
_FALSE_VALUES = {"false", "no", "n", "0", "internal", "private"}


class AssetImportError(ValueError):
    """Raised when the CSV cannot be safely or completely imported."""


@dataclass
class AssetImportResult:
    assets: list[AssetRecord]
    total_rows: int
    skipped_rows: list[tuple[int, str]] = field(default_factory=list)
    truncated: bool = False


class AssetImporter:
    def __init__(self, max_file_bytes: int = 10 * 1024 * 1024, max_rows: int = 50_000):
        self.max_file_bytes = max_file_bytes
        self.max_rows = max_rows

    def import_file(self, path: str) -> AssetImportResult:
        file_path = Path(path)
        if not file_path.is_file():
            raise AssetImportError(f"Asset inventory file not found: {path}")
        if file_path.stat().st_size > self.max_file_bytes:
            raise AssetImportError(
                f"Asset inventory file exceeds the configured {self.max_file_bytes // (1024 * 1024)} MiB limit"
            )
        with file_path.open("r", encoding="utf-8", newline="", errors="replace") as handle:
            return self._import_rows(handle)

    def _import_rows(self, handle: Iterable[str]) -> AssetImportResult:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise AssetImportError("CSV file has no header row")

        column_map = self._resolve_columns(reader.fieldnames)

        assets: list[AssetRecord] = []
        skipped: list[tuple[int, str]] = []
        truncated = False
        total_rows = 0

        for line_number, row in enumerate(reader, start=2):  # header is line 1
            total_rows += 1
            if len(assets) >= self.max_rows:
                truncated = True
                continue
            try:
                asset = self._row_to_asset(row, column_map)
            except AssetImportError as exc:
                skipped.append((line_number, str(exc)))
                continue
            assets.append(asset)

        return AssetImportResult(assets=assets, total_rows=total_rows, skipped_rows=skipped, truncated=truncated)

    @staticmethod
    def _resolve_columns(fieldnames: list[str]) -> dict[str, str]:
        """Map logical column names to actual header names, rejecting ambiguity."""
        normalized = [(name, name.strip().lower()) for name in fieldnames if name]

        seen_lower = [n for _, n in normalized]
        duplicates = {n for n in seen_lower if seen_lower.count(n) > 1}
        if duplicates:
            raise AssetImportError(f"Duplicate CSV columns detected: {', '.join(sorted(duplicates))}")

        def find(aliases: set[str]) -> str | None:
            matches = [orig for orig, low in normalized if low in aliases]
            if len(matches) > 1:
                raise AssetImportError(f"Multiple columns map to the same field: {matches}")
            return matches[0] if matches else None

        hostname_col = find(_HOSTNAME_ALIASES)
        ip_col = find(_IP_ALIASES)
        criticality_col = find(_CRITICALITY_ALIASES)
        internet_facing_col = find(_INTERNET_FACING_ALIASES)
        owner_col = find(_OWNER_ALIASES)
        product_col = find(_PRODUCT_ALIASES)

        if not hostname_col and not ip_col:
            raise AssetImportError(
                "CSV must include at least one of a hostname/host/name column or an ip/ip_address column"
            )
        if not criticality_col:
            raise AssetImportError(
                "CSV must include a criticality column (accepted headers: criticality, importance, tier)"
            )

        return {
            "hostname": hostname_col,
            "ip": ip_col,
            "criticality": criticality_col,
            "internet_facing": internet_facing_col,
            "owner": owner_col,
            "product": product_col,
        }

    @staticmethod
    def _clean(value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not value:
            return None
        if has_control_characters(value):
            raise AssetImportError("field contains control characters")
        return str(spreadsheet_value(value))

    def _row_to_asset(self, row: dict, column_map: dict[str, str]) -> AssetRecord:
        hostname = self._clean(row.get(column_map["hostname"])) if column_map["hostname"] else None
        raw_ip = self._clean(row.get(column_map["ip"])) if column_map["ip"] else None

        ip_address = None
        if raw_ip:
            # Strip the CSV formula-neutralisation prefix (a leading apostrophe)
            # before validating, since it is not part of the actual value.
            candidate = raw_ip[1:] if raw_ip.startswith("'") else raw_ip
            try:
                ip_address = str(ipaddress.ip_address(candidate))
            except ValueError as exc:
                raise AssetImportError(f"invalid IP address: {candidate!r}") from exc

        if not hostname and not ip_address:
            raise AssetImportError("row has neither a usable hostname nor a valid IP address")

        raw_criticality = self._clean(row.get(column_map["criticality"]))
        if not raw_criticality:
            raise AssetImportError("criticality is required")
        criticality = raw_criticality.lstrip("'").lower()
        if criticality not in _VALID_CRITICALITY:
            raise AssetImportError(
                f"criticality must be one of {sorted(_VALID_CRITICALITY)}, got {raw_criticality!r}"
            )

        internet_facing = False
        if column_map["internet_facing"]:
            raw_flag = self._clean(row.get(column_map["internet_facing"]))
            if raw_flag:
                flag = raw_flag.lstrip("'").lower()
                if flag in _TRUE_VALUES:
                    internet_facing = True
                elif flag in _FALSE_VALUES:
                    internet_facing = False
                else:
                    raise AssetImportError(f"internet_facing value not recognised: {raw_flag!r}")

        owner = self._clean(row.get(column_map["owner"])) if column_map["owner"] else None
        product = self._clean(row.get(column_map["product"])) if column_map["product"] else None

        return AssetRecord(
            criticality=criticality,
            hostname=hostname,
            ip_address=ip_address,
            internet_facing=internet_facing,
            owner=owner,
            product=product,
        )
