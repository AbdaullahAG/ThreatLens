"""
Shared streaming/validation helpers for log-format IOC parsers
(Zeek, Suricata, Sysmon, generic JSONL).

Centralises the two things every one of these parsers must do consistently:

1. Stream the file line-by-line rather than loading it fully into memory —
   these logs (conn.log, eve.json, Sysmon exports) can be very large.
2. Never trust extracted values as-is: every candidate IOC is passed
   through ``validate_ioc`` before being accepted, and per-line/per-event
   errors never abort the whole parse — one malformed line is skipped, not
   fatal.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
import os
import stat
from typing import Iterator

from src.models import IOC, IOCType
from src.utils.security import IOCValidationError, validate_ioc


@dataclass
class LogParseResult:
    iocs: list[IOC]
    stats: dict[str, int] = field(default_factory=dict)
    truncated: bool = False
    malformed_lines: int = 0


class LogFileTooLargeError(ValueError):
    """Raised when a log file exceeds the configured size limit."""


MAX_LOG_LINE_CHARS = 1 * 1024 * 1024


def check_file_size(path: str, max_file_bytes: int) -> Path:
    if not isinstance(path, str) or not path or len(path) > 4096 or any(ord(ch) < 32 or ord(ch) == 127 for ch in path):
        raise ValueError("Log file path is invalid")
    file_path = Path(path)
    try:
        with file_path.open("rb") as handle:
            file_stat = os.fstat(handle.fileno())
    except FileNotFoundError:
        raise FileNotFoundError("Log file not found") from None
    if not stat.S_ISREG(file_stat.st_mode):
        raise ValueError("Log input must be a regular file")
    if file_stat.st_size > max_file_bytes:
        raise LogFileTooLargeError("Log file exceeds the configured size limit")
    return file_path


def iter_text_lines(path: str, max_file_bytes: int, max_lines: int) -> Iterator[tuple[int, str, bool]]:
    """
    Stream a text file line-by-line.
    Yields (line_number, line, truncated_flag). Once max_lines is reached,
    yields a final (line_number, "", True) sentinel and stops.
    """
    file_path = check_file_size(path, max_file_bytes)
    with file_path.open("r", encoding="utf-8", errors="replace") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise ValueError("Log input must be a regular file")
        if os.fstat(handle.fileno()).st_size > max_file_bytes:
            raise LogFileTooLargeError("Log file exceeds the configured size limit")
        line_number = 0
        while True:
            line = handle.readline(MAX_LOG_LINE_CHARS + 1)
            if not line:
                return
            line_number += 1
            if line_number > max_lines:
                yield line_number, "", True
                return
            if len(line.rstrip("\r\n")) > MAX_LOG_LINE_CHARS:
                raise LogFileTooLargeError("Log line exceeds the configured per-line limit")
            yield line_number, line.rstrip("\n").rstrip("\r"), False


def iter_jsonl_events(path: str, max_file_bytes: int, max_lines: int) -> Iterator[tuple[int, dict | None]]:
    """
    Stream a JSON-Lines file (one JSON object per line), tolerating
    malformed lines. Yields (line_number, parsed_dict_or_None).
    A None event means the line was malformed and should be skipped by
    the caller (and counted) rather than aborting the whole parse.
    """
    for line_number, raw_line, truncated in iter_text_lines(path, max_file_bytes, max_lines):
        if truncated:
            return
        line = raw_line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except (ValueError, TypeError, RecursionError):
            yield line_number, None
            continue
        yield line_number, event if isinstance(event, dict) else None


class IOCCollector:
    """De-duplicating, validating, size-bounded IOC accumulator."""

    def __init__(self, max_iocs: int, *, allow_private: bool = False):
        self.max_iocs = max_iocs
        self.allow_private = allow_private
        self.iocs: list[IOC] = []
        self.truncated = False
        self._seen: set[str] = set()

    def add(self, value: str | None, ioc_type: IOCType) -> None:
        if not value or self.truncated:
            return
        if len(self.iocs) >= self.max_iocs:
            self.truncated = True
            return
        key = f"{ioc_type}:{value.lower()}"
        if key in self._seen:
            return
        try:
            canonical = validate_ioc(value, ioc_type, allow_private=self.allow_private)
        except IOCValidationError:
            return
        self._seen.add(key)
        self.iocs.append(IOC(value=canonical, ioc_type=ioc_type))

    def stats(self) -> dict[str, int]:
        counts: dict[str, int] = {t.value.lower(): 0 for t in IOCType}
        for ioc in self.iocs:
            counts[ioc.ioc_type.value.lower()] += 1
        return counts
