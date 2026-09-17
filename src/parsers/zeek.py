"""
Zeek Parser — extracts IOCs from Zeek's tab-separated log files
(conn.log, dns.log, http.log, ssl.log, files.log, ...).

Zeek TSV logs carry their own header: ``#separator``, ``#fields`` and
``#types`` directive lines followed by data rows. This parser reads the
header to learn the column layout and separator, then streams data rows
and extracts whichever IOC-relevant columns are present — so it works
across log types (conn/dns/http/ssl/files) without needing to be told
which one it's reading.
"""

from __future__ import annotations

from src.models import IOCType
from src.parsers.common import IOCCollector, LogParseResult, iter_text_lines

_UNSET = {"-", "(empty)", ""}


class ZeekParser:
    def __init__(self, max_file_bytes: int = 50 * 1024 * 1024, max_lines: int = 500_000, max_iocs: int = 5_000):
        self.max_file_bytes = max_file_bytes
        self.max_lines = max_lines
        self.max_iocs = max_iocs

    def parse_file(self, path: str) -> LogParseResult:
        collector = IOCCollector(self.max_iocs)
        malformed = 0

        separator = "\t"
        set_separator = ","
        fields: list[str] | None = None

        for _line_number, line, truncated in iter_text_lines(path, self.max_file_bytes, self.max_lines):
            if truncated:
                collector.truncated = True
                break
            if not line:
                continue

            if line.startswith("#"):
                if line.startswith("#separator "):
                    raw = line[len("#separator "):].strip()
                    separator = _decode_zeek_separator(raw)
                elif line.startswith("#set_separator"):
                    parts = line.split(separator if separator in line else "\t")
                    if len(parts) > 1:
                        set_separator = parts[1] or set_separator
                elif line.startswith("#fields"):
                    fields = line.split(separator)[1:]
                continue

            if fields is None:
                # Data row encountered before a #fields header — can't map columns safely.
                malformed += 1
                continue

            values = line.split(separator)
            if len(values) != len(fields):
                malformed += 1
                continue

            row = dict(zip(fields, values))
            self._extract_row(row, set_separator, collector)
            if collector.truncated:
                break

        return LogParseResult(
            iocs=collector.iocs,
            stats=collector.stats(),
            truncated=collector.truncated,
            malformed_lines=malformed,
        )

    @staticmethod
    def _extract_row(row: dict, set_separator: str, collector: IOCCollector) -> None:
        def get(name: str) -> str | None:
            value = row.get(name)
            return None if value is None or value in _UNSET else value

        def get_set(name: str) -> list[str]:
            value = get(name)
            if not value:
                return []
            return [v for v in value.split(set_separator) if v not in _UNSET]

        # conn.log / most logs
        collector.add(get("id.orig_h"), IOCType.IP)
        collector.add(get("id.resp_h"), IOCType.IP)

        # dns.log
        collector.add(get("query"), IOCType.DOMAIN)
        for answer in get_set("answers"):
            ioc_type = IOCType.IP if _looks_like_ip(answer) else IOCType.DOMAIN
            collector.add(answer, ioc_type)

        # http.log
        host = get("host")
        uri = get("uri")
        collector.add(host, IOCType.DOMAIN)
        if host and uri:
            collector.add(f"http://{host}{uri}", IOCType.URL)

        # ssl.log (SNI)
        collector.add(get("server_name"), IOCType.DOMAIN)

        # files.log
        for hash_field in ("md5", "sha1", "sha256"):
            collector.add(get(hash_field), IOCType.HASH)
        for host_field in ("tx_hosts", "rx_hosts"):
            for host_ip in get_set(host_field):
                collector.add(host_ip, IOCType.IP)


def _decode_zeek_separator(raw: str) -> str:
    """Zeek writes the separator literally as e.g. '\\x09' for a tab."""
    if raw.startswith("\\x"):
        try:
            return chr(int(raw[2:], 16))
        except ValueError:
            return "\t"
    return raw or "\t"


def _looks_like_ip(value: str) -> bool:
    if ":" in value:
        return True
    parts = value.split(".")
    return len(parts) == 4 and all(part.isdigit() for part in parts)
