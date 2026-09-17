"""Unit tests for the Evidence Pack builder (ZIP + manifest chain-of-custody)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from zipfile import ZipFile

from src.decision.cve_decision import Decision, CVEDecisionCard
from src.evidence.pack import EvidencePackBuilder
from src.models import IOC, IOCType, EnrichmentResult


def _results():
    return [
        EnrichmentResult(ioc=IOC("8.8.8.8", IOCType.IP)),
        EnrichmentResult(ioc=IOC("CVE-2021-44228", IOCType.CVE), cvss_score=10.0, cisa_kev=True),
    ]


class TestEvidencePackBuilder:
    def test_build_creates_zip_with_expected_files(self, tmp_path):
        builder = EvidencePackBuilder(output_dir=str(tmp_path))
        zip_path = builder.build("inv-001", _results())
        with ZipFile(zip_path) as archive:
            names = set(archive.namelist())
        assert "investigation.json" in names
        assert "manifest.json" in names
        assert "decision_cards.json" not in names  # none provided

    def test_manifest_hashes_match_file_contents(self, tmp_path):
        builder = EvidencePackBuilder(output_dir=str(tmp_path))
        zip_path = builder.build("inv-002", _results())
        with ZipFile(zip_path) as archive:
            manifest = json.loads(archive.read("manifest.json"))
            for name, meta in manifest["files"].items():
                if name == "manifest.json":
                    continue
                content = archive.read(name)
                assert hashlib.sha256(content).hexdigest() == meta["sha256"]
                assert len(content) == meta["bytes"]

    def test_includes_decision_cards_and_assets_when_provided(self, tmp_path):
        card = CVEDecisionCard(cve_id="CVE-2021-44228", decision=Decision.ISOLATE, reasons=["KEV listed"])
        assets = [{"hostname": "web01", "criticality": "critical"}]
        builder = EvidencePackBuilder(output_dir=str(tmp_path))
        zip_path = builder.build("inv-003", _results(), decision_cards=[card], matched_assets=assets)
        with ZipFile(zip_path) as archive:
            names = set(archive.namelist())
            cards = json.loads(archive.read("decision_cards.json"))
            loaded_assets = json.loads(archive.read("assets.json"))
        assert "decision_cards.json" in names and "assets.json" in names
        assert cards[0]["decision"] == "Isolate"
        assert loaded_assets[0]["hostname"] == "web01"

    def test_manifest_records_tool_version_and_investigation_id(self, tmp_path):
        builder = EvidencePackBuilder(output_dir=str(tmp_path))
        zip_path = builder.build("inv-004", _results())
        with ZipFile(zip_path) as archive:
            manifest = json.loads(archive.read("manifest.json"))
        assert manifest["investigation_id"] == "inv-004"
        assert manifest["tool"] == "ThreatLens"
        assert manifest["version"] == "2.2.0"

    def test_secret_like_strings_are_redacted(self, tmp_path):
        results = _results()
        results[0].errors["abuseipdb"] = "request failed: api_key=SHOULD-NOT-APPEAR&foo=bar"
        builder = EvidencePackBuilder(output_dir=str(tmp_path))
        zip_path = builder.build("inv-005", results)
        with ZipFile(zip_path) as archive:
            content = archive.read("investigation.json").decode("utf-8")
        assert "SHOULD-NOT-APPEAR" not in content
        assert "REDACTED" in content

    def test_output_dir_created_if_missing(self, tmp_path):
        target = tmp_path / "nested" / "evidence"
        builder = EvidencePackBuilder(output_dir=str(target))
        zip_path = builder.build("inv-006", _results())
        assert Path(zip_path).exists()
