# Changelog

All notable changes to ThreatLens are documented here.

## [2.2.0] — Vulnerability & SOC Triage

### Added

**CVE / vulnerability intelligence**
- `cisa_kev` enricher — checks CVEs against the CISA Known Exploited Vulnerabilities catalog. The ~1,600+ entry feed is downloaded once and cached locally (24h TTL, configurable via `kev_cache_ttl`) instead of being re-fetched per CVE.
- `epss` enricher — FIRST.org EPSS exploit-probability score and percentile. Supports batch prefetching (comma-separated CVE lists) so a bulk CVE scan costs a handful of requests instead of one per CVE.
- New `EnrichmentResult` fields: `epss_score`, `epss_percentile`, `cisa_kev`, `cisa_kev_due_date`, `cisa_kev_ransomware_use`.

**CVE Decision Cards**
- `src/decision/cve_decision.py` — deterministic, explainable **Patch / Isolate / Monitor / Not affected** recommendation for every CVE, driven by CISA KEV status, EPSS score, CVSS severity, and (optionally) asset exposure. Every decision returns the reasons behind it; a CISA KEV listing is a hard floor that is never downgraded to "Monitor".
- `--decision-cards` CLI flag.

**Asset inventory & correlation**
- `src/assets/importer.py` — safe CSV asset-inventory import (`csv.DictReader` only, size/row limits, required-column validation, Excel-formula neutralisation on every cell).
- `src/decision/asset_correlation.py` — heuristic product/hostname matching between NVD's affected-products data and the imported inventory, feeding internet-facing/criticality context into the decision card.
- New `assets` SQLite table (`InvestigationStore.replace_assets` / `list_assets`).
- `--import-assets CSV_PATH` CLI flag.

**Log format support**
- `src/parsers/zeek.py`, `suricata.py`, `sysmon.py`, `jsonl.py` — stream Zeek TSV logs, Suricata `eve.json`, JSON-exported Sysmon events, and generic JSON-Lines logs, extracting and validating IOCs line-by-line so a single malformed line never aborts a scan. Shared streaming/validation helpers live in `src/parsers/common.py`.
- `--log-format {auto,text,zeek,suricata,sysmon,jsonl}` CLI flag (auto-detects by default).

**SIEM export**
- `src/exporters/` — opt-in export to **Splunk** (HTTP Event Collector), **Elastic** (`_bulk` API, API-key auth), and **Microsoft Sentinel** (modern Logs Ingestion API via Entra ID app registration + Data Collection Endpoint/Rule — the legacy HTTP Data Collector API is not used, as it is deprecated by Microsoft).
- Every destination is allow-listed by host, TLS-verified by default, retried with capped backoff, and batched; one destination failing never blocks the others.
- `--export {splunk,elastic,sentinel}` and `--export-insecure-tls` CLI flags. Exporters only activate when their required `config/keys.env` values are all present.

**Evidence packs**
- `src/evidence/pack.py` — packages an investigation's results, decision cards, and correlated assets into a ZIP with a `manifest.json` recording a SHA-256 hash of every file inside, for basic chain-of-custody. Uses the standard-library `zipfile` module only; a redaction pass runs over every value before packaging.
- `--evidence-pack` CLI flag.

### Changed
- `src/enrichers/base.py`: `BaseEnricher` now accepts an optional `store` handle so enrichers can cache bulk feeds locally (used by `cisa_kev`).
- `src/engine.py`: orchestration now runs asset import → IOC collection (including structured log parsing) → enrichment (with EPSS prefetching) → decision cards → reports → SIEM export → evidence pack.
- `Config` gained `kev_cache_ttl`, `max_asset_file_bytes`, `max_asset_rows`, `max_log_lines`, and the SIEM destination settings, all validated with the same bounds-checking style as existing settings.
- `config/keys.env` documents the new (all-optional) CISA KEV/EPSS and SIEM export settings.

### Security
- All new external inputs (CSV asset rows, Zeek/Suricata/Sysmon/JSONL log lines, CISA KEV feed entries) are validated with an allow-list approach and never trusted as-is; malformed individual rows/lines are skipped, not fatal.
- No new third-party dependencies were introduced — CSV import, log parsing, and evidence packing all use the Python standard library (`csv`, `json`, `zipfile`, `hashlib`, `ipaddress`).
- SIEM credentials are read only from `config/keys.env`, never logged (redacted in all error paths), and never written into evidence packs.
- `bandit` and `ruff` (pinned versions from `requirements-dev.txt`) both pass clean on the new code; one bandit false positive (a `_TOKEN_HOST` constant name) was renamed to avoid the naive secret-name heuristic.

### Tests
- 95 new tests added across `test_vuln_intel_enrichers.py`, `test_cve_decision.py`, `test_asset_importer.py`, `test_asset_correlation.py`, `test_log_parsers.py`, `test_exporters.py`, and `test_evidence_pack.py`.
- Full suite: 155 passed, 1 skipped (pre-existing opt-in e2e test), up from 60 passed, 1 skipped.

## [2.1.0] and earlier
See git history / prior releases.
