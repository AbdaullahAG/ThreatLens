"""
Sysmon Parser — extracts IOCs from Sysmon Windows Event Log exports
converted to JSON Lines (e.g. via ``evtx_dump`` / ``python-evtx`` /
Windows Event Forwarding pipelines that emit JSON).

Only JSON input is accepted. Raw XML .evtx-derived XML is intentionally
not parsed directly by this module: Python's standard-library XML parsers
are vulnerable to entity-expansion and external-entity attacks on
untrusted input, and no safe (defused) XML library ships in this
project's dependencies. Convert XML exports to JSON first (most Sysmon
export tooling supports this natively) before handing the file to
ThreatLens.

Covers the two event types that carry the most IOC value:
  * Event ID 1  — Process Create (Hashes, Image, CommandLine)
  * Event ID 3  — Network Connect (DestinationIp, DestinationHostname)
"""

from __future__ import annotations

from src.models import IOCType
from src.parsers.common import IOCCollector, LogParseResult, iter_jsonl_events

_PROCESS_CREATE = "1"
_NETWORK_CONNECT = "3"


def _event_data(event: dict) -> dict:
    """
    Normalise the handful of shapes JSON-exported Sysmon events show up in:
    a flat dict, an ``EventData`` dict, or the nested Windows Event Log
    JSON shape ``{"Event": {"System": {...}, "EventData": {"Data": [...]}}}``.
    """
    if "EventData" in event and isinstance(event["EventData"], dict):
        return event["EventData"]

    nested = event.get("Event")
    if isinstance(nested, dict):
        event_data = nested.get("EventData")
        if isinstance(event_data, dict):
            data = event_data.get("Data")
            if isinstance(data, list):
                out = {}
                for item in data:
                    if isinstance(item, dict) and "@Name" in item:
                        out[item["@Name"]] = item.get("#text")
                return out
            if isinstance(data, dict):
                return data
    return event


def _event_id(event: dict) -> str | None:
    if "EventID" in event:
        return str(event["EventID"])
    system = event.get("Event", {}).get("System") if isinstance(event.get("Event"), dict) else None
    if isinstance(system, dict):
        event_id = system.get("EventID")
        if isinstance(event_id, dict):
            return str(event_id.get("#text", ""))
        if event_id is not None:
            return str(event_id)
    return None


class SysmonParser:
    def __init__(self, max_file_bytes: int = 50 * 1024 * 1024, max_lines: int = 500_000, max_iocs: int = 5_000):
        self.max_file_bytes = max_file_bytes
        self.max_lines = max_lines
        self.max_iocs = max_iocs

    def parse_file(self, path: str) -> LogParseResult:
        collector = IOCCollector(self.max_iocs)
        malformed = 0

        for _line_number, event in iter_jsonl_events(path, self.max_file_bytes, self.max_lines):
            if event is None:
                malformed += 1
                continue
            event_id = _event_id(event)
            data = _event_data(event)
            if not isinstance(data, dict):
                continue
            if event_id == _PROCESS_CREATE:
                self._extract_process_create(data, collector)
            elif event_id == _NETWORK_CONNECT:
                self._extract_network_connect(data, collector)
            if collector.truncated:
                break

        return LogParseResult(
            iocs=collector.iocs,
            stats=collector.stats(),
            truncated=collector.truncated,
            malformed_lines=malformed,
        )

    @staticmethod
    def _extract_process_create(data: dict, collector: IOCCollector) -> None:
        hashes_field = data.get("Hashes")
        if isinstance(hashes_field, str):
            # Format: "MD5=...,SHA256=...,IMPHASH=..."
            for pair in hashes_field.split(","):
                if "=" not in pair:
                    continue
                algo, _, value = pair.partition("=")
                if algo.strip().upper() in ("MD5", "SHA1", "SHA256"):
                    collector.add(value.strip(), IOCType.HASH)

    @staticmethod
    def _extract_network_connect(data: dict, collector: IOCCollector) -> None:
        collector.add(data.get("DestinationIp"), IOCType.IP)
        collector.add(data.get("SourceIp"), IOCType.IP)
        collector.add(data.get("DestinationHostname"), IOCType.DOMAIN)
