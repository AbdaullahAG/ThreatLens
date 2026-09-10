"""
CLI end-to-end test — runs the real main.py binary in a subprocess.

Skipped by default; enable with:
    pytest tests/test_cli_e2e.py --run-e2e -v

The test exercises:
    python main.py -c CVE-2021-44228 --apis nvd --format json \\
                   --output <tmp_dir> --no-cache

Assertions
──────────
* Process exits with code 0.
* A .json file is written to <tmp_dir>.
* The JSON is valid and contains the expected IOC identity fields.
* The result verdict is one of the well-known verdict strings.
* NVD data is populated (cvss_score present and > 0).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


KNOWN_VERDICTS = {"Critical", "High", "Medium", "Low", "Unknown"}
CVE_ID = "CVE-2021-44228"

# Force UTF-8 output on all platforms — avoids Windows CP1252 crash when
# Rich outputs Unicode checkmarks (✓ U+2713, etc.).
_UTF8_ENV = {**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"}


@pytest.mark.e2e
def test_cli_nvd_json_e2e(tmp_path: Path):
    """Full CLI run against the real NVD API; verifies JSON output structure."""
    result = subprocess.run(
        [
            sys.executable, "main.py",
            "-c", CVE_ID,
            "--apis", "nvd",
            "--format", "json",
            "--output", str(tmp_path),
            "--no-cache",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
        env=_UTF8_ENV,
        cwd=Path(__file__).parent.parent,  # project root
    )

    # ── Exit code ────────────────────────────────────────────────────────────
    assert result.returncode == 0, (
        f"main.py exited {result.returncode}\n"
        f"stdout:\n{result.stdout}\n"
        f"stderr:\n{result.stderr}"
    )

    # ── Output file exists ───────────────────────────────────────────────────
    json_files = list(tmp_path.glob("*.json"))
    assert json_files, (
        f"No .json file found in {tmp_path}\n"
        f"stdout:\n{result.stdout}"
    )

    # ── JSON is valid ────────────────────────────────────────────────────────
    with open(json_files[0], encoding="utf-8") as f:
        data = json.load(f)

    # ── Structure ────────────────────────────────────────────────────────────
    assert "meta" in data, "JSON report missing 'meta' key"
    assert "results" in data, "JSON report missing 'results' key"
    assert data["meta"]["total_iocs"] == 1

    # ── IOC identity ─────────────────────────────────────────────────────────
    entry = data["results"][0]
    assert entry["ioc"]["value"] == CVE_ID, (
        f"Unexpected IOC value: {entry['ioc']['value']!r}"
    )
    assert entry["ioc"]["type"].upper() == "CVE"

    # ── Verdict ──────────────────────────────────────────────────────────────
    assert entry["verdict"] in KNOWN_VERDICTS, (
        f"Unexpected verdict: {entry['verdict']!r}"
    )

    # ── NVD data populated ───────────────────────────────────────────────────
    assert entry.get("cvss_score") is not None and entry["cvss_score"] > 0, (
        f"cvss_score missing or zero: {entry.get('cvss_score')!r}"
    )
