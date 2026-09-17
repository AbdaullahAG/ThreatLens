"""Unit tests for the Zeek, Suricata, Sysmon, and generic JSONL log parsers."""

from __future__ import annotations

import json

import pytest

from src.models import IOCType
from src.parsers.common import LogFileTooLargeError
from src.parsers.jsonl import JSONLParser
from src.parsers.suricata import SuricataParser
from src.parsers.sysmon import SysmonParser
from src.parsers.zeek import ZeekParser


def _write(tmp_path, name: str, content: str) -> str:
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return str(path)


# ── Zeek ──────────────────────────────────────────────────────────────────

class TestZeekParser:
    def test_conn_log_extracts_public_ips_only(self, tmp_path):
        content = (
            "#separator \\x09\n"
            "#fields\tid.orig_h\tid.resp_h\n"
            "192.168.1.5\t45.33.32.156\n"
        )
        path = _write(tmp_path, "conn.log", content)
        result = ZeekParser().parse_file(path)
        values = {i.value for i in result.iocs}
        assert "45.33.32.156" in values
        assert "192.168.1.5" not in values  # private, rejected by validate_ioc

    def test_dns_log_extracts_query_and_answers(self, tmp_path):
        content = (
            "#separator \\x09\n"
            "#fields\tquery\tanswers\n"
            "evil.example.com\t45.33.32.156,other.example.com\n"
        )
        path = _write(tmp_path, "dns.log", content)
        result = ZeekParser().parse_file(path)
        values = {i.value for i in result.iocs}
        assert "evil.example.com" in values
        assert "45.33.32.156" in values
        assert "other.example.com" in values

    def test_http_log_builds_url(self, tmp_path):
        content = (
            "#separator \\x09\n"
            "#fields\thost\turi\n"
            "evil.example.com\t/payload.exe\n"
        )
        path = _write(tmp_path, "http.log", content)
        result = ZeekParser().parse_file(path)
        urls = [i.value for i in result.iocs if i.ioc_type == IOCType.URL]
        assert any("evil.example.com/payload.exe" in u for u in urls)

    def test_files_log_extracts_hashes(self, tmp_path):
        sha256 = "a" * 64
        content = (
            "#separator \\x09\n"
            "#fields\tmd5\tsha1\tsha256\n"
            f"d41d8cd98f00b204e9800998ecf8427e\t{'b' * 40}\t{sha256}\n"
        )
        path = _write(tmp_path, "files.log", content)
        result = ZeekParser().parse_file(path)
        hashes = {i.value for i in result.iocs if i.ioc_type == IOCType.HASH}
        assert sha256 in hashes

    def test_unset_values_are_skipped(self, tmp_path):
        content = "#separator \\x09\n#fields\tid.orig_h\tid.resp_h\n-\t-\n"
        path = _write(tmp_path, "conn.log", content)
        result = ZeekParser().parse_file(path)
        assert result.iocs == []

    def test_malformed_row_before_header_is_skipped_not_fatal(self, tmp_path):
        content = "garbage\trow\n#separator \\x09\n#fields\tid.resp_h\n45.33.32.156\n"
        path = _write(tmp_path, "conn.log", content)
        result = ZeekParser().parse_file(path)
        assert any(i.value == "45.33.32.156" for i in result.iocs)
        assert result.malformed_lines >= 1

    def test_oversized_file_rejected(self, tmp_path):
        content = "#separator \\x09\n#fields\tid.resp_h\n" + "\n".join(f"1.1.1.{i}" for i in range(500))
        path = _write(tmp_path, "conn.log", content)
        with pytest.raises(LogFileTooLargeError):
            ZeekParser(max_file_bytes=20).parse_file(path)


# ── Suricata ──────────────────────────────────────────────────────────────

class TestSuricataParser:
    def test_alert_event_extracts_ips(self, tmp_path):
        line = json.dumps({"event_type": "alert", "src_ip": "192.168.1.5", "dest_ip": "45.33.32.156"})
        path = _write(tmp_path, "eve.json", line + "\n")
        result = SuricataParser().parse_file(path)
        values = {i.value for i in result.iocs}
        assert "45.33.32.156" in values
        assert "192.168.1.5" not in values

    def test_dns_event_extracts_rrname_and_answers(self, tmp_path):
        event = {
            "event_type": "dns",
            "dns": {"rrname": "evil.example.com", "answers": [{"rrtype": "A", "rdata": "45.33.32.156"}]},
        }
        path = _write(tmp_path, "eve.json", json.dumps(event) + "\n")
        result = SuricataParser().parse_file(path)
        values = {i.value for i in result.iocs}
        assert "evil.example.com" in values
        assert "45.33.32.156" in values

    def test_http_event_builds_url(self, tmp_path):
        event = {"event_type": "http", "http": {"hostname": "evil.example.com", "url": "/x.exe"}}
        path = _write(tmp_path, "eve.json", json.dumps(event) + "\n")
        result = SuricataParser().parse_file(path)
        urls = [i.value for i in result.iocs if i.ioc_type == IOCType.URL]
        assert any("evil.example.com/x.exe" in u for u in urls)

    def test_tls_sni_extracted(self, tmp_path):
        event = {"event_type": "tls", "tls": {"sni": "evil.example.com"}}
        path = _write(tmp_path, "eve.json", json.dumps(event) + "\n")
        result = SuricataParser().parse_file(path)
        assert any(i.value == "evil.example.com" for i in result.iocs)

    def test_fileinfo_hash_extracted(self, tmp_path):
        sha256 = "c" * 64
        event = {"event_type": "fileinfo", "fileinfo": {"sha256": sha256}}
        path = _write(tmp_path, "eve.json", json.dumps(event) + "\n")
        result = SuricataParser().parse_file(path)
        assert any(i.value == sha256 for i in result.iocs)

    def test_malformed_line_is_skipped_not_fatal(self, tmp_path):
        content = "{not valid json\n" + json.dumps({"event_type": "alert", "dest_ip": "45.33.32.156"}) + "\n"
        path = _write(tmp_path, "eve.json", content)
        result = SuricataParser().parse_file(path)
        assert result.malformed_lines == 1
        assert any(i.value == "45.33.32.156" for i in result.iocs)

    def test_irrelevant_event_type_ignored(self, tmp_path):
        event = {"event_type": "stats"}
        path = _write(tmp_path, "eve.json", json.dumps(event) + "\n")
        result = SuricataParser().parse_file(path)
        assert result.iocs == []


# ── Sysmon ────────────────────────────────────────────────────────────────

class TestSysmonParser:
    def test_process_create_extracts_hashes(self, tmp_path):
        sha256 = "d" * 64
        event = {"EventID": "1", "Hashes": f"MD5=d41d8cd98f00b204e9800998ecf8427e,SHA256={sha256}"}
        path = _write(tmp_path, "sysmon.json", json.dumps(event) + "\n")
        result = SysmonParser().parse_file(path)
        values = {i.value for i in result.iocs}
        assert sha256 in values
        assert "d41d8cd98f00b204e9800998ecf8427e" in values

    def test_network_connect_extracts_ip_and_hostname(self, tmp_path):
        event = {
            "EventID": "3",
            "DestinationIp": "45.33.32.156",
            "DestinationHostname": "evil.example.com",
        }
        path = _write(tmp_path, "sysmon.json", json.dumps(event) + "\n")
        result = SysmonParser().parse_file(path)
        values = {i.value for i in result.iocs}
        assert "45.33.32.156" in values
        assert "evil.example.com" in values

    def test_nested_windows_event_log_shape(self, tmp_path):
        event = {
            "Event": {
                "System": {"EventID": {"#text": "3"}},
                "EventData": {"Data": [
                    {"@Name": "DestinationIp", "#text": "45.33.32.156"},
                ]},
            }
        }
        path = _write(tmp_path, "sysmon.json", json.dumps(event) + "\n")
        result = SysmonParser().parse_file(path)
        assert any(i.value == "45.33.32.156" for i in result.iocs)

    def test_other_event_ids_ignored(self, tmp_path):
        event = {"EventID": "7", "ImageLoaded": "C:\\evil.dll"}
        path = _write(tmp_path, "sysmon.json", json.dumps(event) + "\n")
        result = SysmonParser().parse_file(path)
        assert result.iocs == []

    def test_malformed_line_skipped(self, tmp_path):
        content = "not json at all\n"
        path = _write(tmp_path, "sysmon.json", content)
        result = SysmonParser().parse_file(path)
        assert result.malformed_lines == 1


# ── Generic JSONL ─────────────────────────────────────────────────────────

class TestJSONLParser:
    def test_extracts_iocs_from_arbitrary_schema(self, tmp_path):
        event = {"message": "connection from 45.33.32.156 to evil.example.com", "level": "warn"}
        path = _write(tmp_path, "custom.jsonl", json.dumps(event) + "\n")
        result = JSONLParser().parse_file(path)
        values = {i.value for i in result.iocs}
        assert "45.33.32.156" in values
        assert "evil.example.com" in values

    def test_nested_objects_are_flattened(self, tmp_path):
        event = {"details": {"nested": {"hash": "d41d8cd98f00b204e9800998ecf8427e"}}}
        path = _write(tmp_path, "custom.jsonl", json.dumps(event) + "\n")
        result = JSONLParser().parse_file(path)
        assert any(i.value == "d41d8cd98f00b204e9800998ecf8427e" for i in result.iocs)

    def test_malformed_line_is_not_fatal(self, tmp_path):
        content = "{broken\n" + json.dumps({"msg": "CVE-2021-44228 exploited"}) + "\n"
        path = _write(tmp_path, "custom.jsonl", content)
        result = JSONLParser().parse_file(path)
        assert result.malformed_lines == 1
        assert any(i.value == "CVE-2021-44228" for i in result.iocs)

    def test_deeply_nested_input_does_not_crash(self, tmp_path):
        nested: dict = {"v": "45.33.32.156"}
        for _ in range(30):
            nested = {"n": nested}
        path = _write(tmp_path, "custom.jsonl", json.dumps(nested) + "\n")
        result = JSONLParser().parse_file(path)
        # Should not raise; deep nesting is simply bounded.
        assert isinstance(result.iocs, list)
