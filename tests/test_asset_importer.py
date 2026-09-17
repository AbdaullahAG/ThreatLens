"""Unit tests for the CSV Asset Inventory importer."""

from __future__ import annotations

import pytest

from src.assets.importer import AssetImportError, AssetImporter


def _write(tmp_path, name: str, content: str) -> str:
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return str(path)


class TestBasicImport:
    def test_imports_valid_rows(self, tmp_path):
        csv_text = (
            "hostname,ip,criticality,internet_facing,owner,product\n"
            "web01,203.0.113.10,critical,true,secops,nginx\n"
            "db01,10.0.0.5,high,no,dba-team,postgres\n"
        )
        path = _write(tmp_path, "assets.csv", csv_text)
        result = AssetImporter().import_file(path)
        assert result.total_rows == 2
        assert len(result.assets) == 2
        assert not result.skipped_rows
        web = next(a for a in result.assets if a.hostname == "web01")
        assert web.internet_facing is True
        assert web.criticality == "critical"

    def test_ip_only_row_accepted(self, tmp_path):
        path = _write(tmp_path, "assets.csv", "ip,criticality\n198.51.100.4,medium\n")
        result = AssetImporter().import_file(path)
        assert result.assets[0].ip_address == "198.51.100.4"
        assert result.assets[0].hostname is None

    def test_hostname_only_row_accepted(self, tmp_path):
        path = _write(tmp_path, "assets.csv", "hostname,criticality\nfileserver,low\n")
        result = AssetImporter().import_file(path)
        assert result.assets[0].hostname == "fileserver"


class TestColumnValidation:
    def test_missing_criticality_column_rejected(self, tmp_path):
        path = _write(tmp_path, "assets.csv", "hostname\nweb01\n")
        with pytest.raises(AssetImportError, match="criticality"):
            AssetImporter().import_file(path)

    def test_missing_identifier_columns_rejected(self, tmp_path):
        path = _write(tmp_path, "assets.csv", "criticality,owner\nhigh,team\n")
        with pytest.raises(AssetImportError, match="hostname"):
            AssetImporter().import_file(path)

    def test_duplicate_columns_rejected(self, tmp_path):
        path = _write(tmp_path, "assets.csv", "hostname,hostname,criticality\na,b,high\n")
        with pytest.raises(AssetImportError, match="Duplicate"):
            AssetImporter().import_file(path)

    def test_empty_file_no_header_rejected(self, tmp_path):
        path = _write(tmp_path, "assets.csv", "")
        with pytest.raises(AssetImportError):
            AssetImporter().import_file(path)


class TestRowValidation:
    def test_invalid_criticality_skipped_not_fatal(self, tmp_path):
        csv_text = "hostname,criticality\nweb01,supercritical\nweb02,high\n"
        path = _write(tmp_path, "assets.csv", csv_text)
        result = AssetImporter().import_file(path)
        assert len(result.assets) == 1
        assert result.assets[0].hostname == "web02"
        assert len(result.skipped_rows) == 1

    def test_invalid_ip_skipped(self, tmp_path):
        csv_text = "ip,criticality\nnot-an-ip,high\n203.0.113.5,high\n"
        path = _write(tmp_path, "assets.csv", csv_text)
        result = AssetImporter().import_file(path)
        assert len(result.assets) == 1

    def test_row_missing_both_identifiers_skipped(self, tmp_path):
        csv_text = "hostname,ip,criticality\n,,high\nweb01,,high\n"
        path = _write(tmp_path, "assets.csv", csv_text)
        result = AssetImporter().import_file(path)
        assert len(result.assets) == 1

    def test_unrecognised_internet_facing_value_skipped(self, tmp_path):
        csv_text = "hostname,criticality,internet_facing\nweb01,high,maybe\nweb02,high,yes\n"
        path = _write(tmp_path, "assets.csv", csv_text)
        result = AssetImporter().import_file(path)
        assert len(result.assets) == 1
        assert result.assets[0].hostname == "web02"


class TestSecurityHardening:
    def test_formula_prefixed_cells_are_neutralised(self, tmp_path):
        csv_text = "hostname,criticality,owner\n=cmd|'/c calc'!A1,high,team\n"
        path = _write(tmp_path, "assets.csv", csv_text)
        result = AssetImporter().import_file(path)
        assert result.assets[0].hostname.startswith("'")

    def test_oversized_file_rejected(self, tmp_path):
        csv_text = "hostname,criticality\n" + "\n".join(f"h{i},low" for i in range(100))
        path = _write(tmp_path, "assets.csv", csv_text)
        importer = AssetImporter(max_file_bytes=10)
        with pytest.raises(AssetImportError, match="exceeds"):
            importer.import_file(path)

    def test_row_cap_truncates(self, tmp_path):
        csv_text = "hostname,criticality\n" + "\n".join(f"h{i},low" for i in range(20))
        path = _write(tmp_path, "assets.csv", csv_text)
        importer = AssetImporter(max_rows=5)
        result = importer.import_file(path)
        assert len(result.assets) == 5
        assert result.truncated is True

    def test_control_characters_rejected(self, tmp_path):
        path = tmp_path / "assets.csv"
        path.write_bytes(b"hostname,criticality\nweb\x0101,high\n")
        result = AssetImporter().import_file(str(path))
        assert not result.assets
        assert len(result.skipped_rows) == 1

    def test_missing_file_raises(self):
        with pytest.raises(AssetImportError, match="not found"):
            AssetImporter().import_file("/nonexistent/assets.csv")


class TestStoragePersistence:
    def test_replace_and_list_assets(self, tmp_path):
        from src.storage import InvestigationStore

        csv_text = "hostname,criticality\nweb01,high\nweb02,low\n"
        path = _write(tmp_path, "assets.csv", csv_text)
        result = AssetImporter().import_file(path)

        store = InvestigationStore(str(tmp_path / "inv.db"))
        count = store.replace_assets(result.assets, source_file=path)
        assert count == 2
        rows = store.list_assets()
        assert {r["hostname"] for r in rows} == {"web01", "web02"}

    def test_replace_assets_clears_previous_import(self, tmp_path):
        from src.storage import InvestigationStore

        store = InvestigationStore(str(tmp_path / "inv.db"))
        first_csv = _write(tmp_path, "a.csv", "hostname,criticality\nweb01,high\n")
        second_csv = _write(tmp_path, "b.csv", "hostname,criticality\nweb02,low\n")

        store.replace_assets(AssetImporter().import_file(first_csv).assets, source_file=first_csv)
        store.replace_assets(AssetImporter().import_file(second_csv).assets, source_file=second_csv)

        rows = store.list_assets()
        assert len(rows) == 1
        assert rows[0]["hostname"] == "web02"
