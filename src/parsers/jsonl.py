"""
Generic JSONL Parser — extracts IOCs from arbitrary JSON-Lines log files
(one JSON object per line) whose schema isn't one of the specifically
supported formats (Zeek/Suricata/Sysmon).

Each event's string leaf values are flattened and run through the same
regex-based extraction/validation used by ``IOCParser`` for free-text logs,
so this format-agnostic path shares its extraction logic with the plain
text parser instead of re-implementing IOC pattern matching a second time.
"""

from __future__ import annotations

from typing import Any

from src.models import IOCType
from src.parsers.common import LogParseResult, iter_jsonl_events
from src.parsers.ioc_parser import IOCParser


def _flatten_strings(value: Any, out: list[str], _depth: int = 0) -> None:
    if _depth > 20:  # bound recursion on pathological/nested input
        return
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, dict):
        for v in value.values():
            _flatten_strings(v, out, _depth + 1)
    elif isinstance(value, list):
        for v in value[:1000]:  # bound very large arrays
            _flatten_strings(v, out, _depth + 1)


class JSONLParser:
    """Streaming, schema-agnostic JSON-Lines IOC extractor."""

    def __init__(self, max_file_bytes: int = 20 * 1024 * 1024, max_lines: int = 200_000, max_iocs: int = 5_000):
        self.max_file_bytes = max_file_bytes
        self.max_lines = max_lines
        self.max_iocs = max_iocs
        self._text_parser = IOCParser(max_file_bytes=max_file_bytes, max_iocs=max_iocs)

    def parse_file(self, path: str) -> LogParseResult:
        all_iocs: dict[str, object] = {}
        malformed = 0
        truncated = False

        for _line_number, event in iter_jsonl_events(path, self.max_file_bytes, self.max_lines):
            if len(all_iocs) >= self.max_iocs:
                truncated = True
                break
            if event is None:
                malformed += 1
                continue
            strings: list[str] = []
            _flatten_strings(event, strings)
            if not strings:
                continue
            sub_result = self._text_parser.parse_text("\n".join(strings))
            for ioc in sub_result.iocs:
                key = f"{ioc.ioc_type}:{ioc.value.lower()}"
                if key not in all_iocs and len(all_iocs) < self.max_iocs:
                    all_iocs[key] = ioc
            if sub_result.truncated:
                truncated = True

        iocs = list(all_iocs.values())
        stats = {t.value.lower(): 0 for t in IOCType}
        for ioc in iocs:
            stats[ioc.ioc_type.value.lower()] += 1

        return LogParseResult(iocs=iocs, stats=stats, truncated=truncated, malformed_lines=malformed)
