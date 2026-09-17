"""
Suricata Parser — extracts IOCs from Suricata's ``eve.json`` output
(one JSON event per line: alert, dns, http, tls, fileinfo, flow, ...).

Streams the file line-by-line via the shared JSONL reader; a malformed
line is skipped and counted, never fatal to the rest of the parse. Every
extracted value is validated through ``validate_ioc`` before acceptance.
"""

from __future__ import annotations

from src.models import IOCType
from src.parsers.common import IOCCollector, LogParseResult, iter_jsonl_events

_RELEVANT_EVENT_TYPES = {"alert", "dns", "http", "tls", "fileinfo", "flow", "ssh", "smtp"}


class SuricataParser:
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
            if event.get("event_type") not in _RELEVANT_EVENT_TYPES:
                continue
            self._extract_event(event, collector)
            if collector.truncated:
                break

        return LogParseResult(
            iocs=collector.iocs,
            stats=collector.stats(),
            truncated=collector.truncated,
            malformed_lines=malformed,
        )

    @staticmethod
    def _extract_event(event: dict, collector: IOCCollector) -> None:
        collector.add(event.get("src_ip"), IOCType.IP)
        collector.add(event.get("dest_ip"), IOCType.IP)

        dns = event.get("dns")
        if isinstance(dns, dict):
            collector.add(dns.get("rrname"), IOCType.DOMAIN)
            for answer in dns.get("answers", []) or []:
                if isinstance(answer, dict) and answer.get("rrtype") in ("A", "AAAA"):
                    collector.add(answer.get("rdata"), IOCType.IP)

        http = event.get("http")
        if isinstance(http, dict):
            hostname = http.get("hostname")
            collector.add(hostname, IOCType.DOMAIN)
            url_path = http.get("url")
            if hostname and url_path:
                scheme = "https" if event.get("app_proto") == "tls" else "http"
                collector.add(f"{scheme}://{hostname}{url_path}", IOCType.URL)

        tls = event.get("tls")
        if isinstance(tls, dict):
            collector.add(tls.get("sni"), IOCType.DOMAIN)

        fileinfo = event.get("fileinfo")
        if isinstance(fileinfo, dict):
            for hash_field in ("md5", "sha1", "sha256"):
                collector.add(fileinfo.get(hash_field), IOCType.HASH)
