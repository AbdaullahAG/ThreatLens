<div align="center">
  <img src="./screenshots/banner.svg" alt="ThreatLens — Multi-Source Threat Intelligence CLI" width="100%">

  <br> 

[![Awesome](https://awesome.re/badge.svg)](https://github.com/jivoi/awesome-osint)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: PolyForm Noncommercial](https://img.shields.io/badge/license-PolyForm%20Noncommercial-lightgrey.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-60%20passed-brightgreen.svg)](tests/)
[![CI](https://img.shields.io/badge/CI-GitHub%20Actions-2088FF.svg)](.github/workflows/security.yml)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](#-contributing)
[![Maintained](https://img.shields.io/badge/maintained-yes-success.svg)](#)

  <br>

  <p><b>Investigate IPs, domains, hashes, and CVEs across 6 free threat intel APIs — without switching between browser tabs.</b></p>

  <p>
    <a href="#-quick-start"><b>Quick Start</b></a> ·
    <a href="#-usage"><b>Usage</b></a> ·
    <a href="#️-architecture"><b>Architecture</b></a> ·
    <a href="#-api-keys"><b>API Keys</b></a> ·
    <a href="#-screenshots"><b>Screenshots</b></a> ·
    <a href="#-contributing"><b>Contributing</b></a>
  </p>
</div>

<br>

> 🚀 Proudly featured in the official **[Awesome OSINT](https://github.com/jivoi/awesome-osint)** repository.

---

## 📖 Overview

**ThreatLens** is a single command-line tool that unifies threat intelligence lookups across the most trusted free OSINT sources. Instead of pasting an IP into five different websites, ThreatLens queries them all in parallel, normalizes the results, and gives you a clear verdict — in the terminal, or in a polished, color-coded Excel/JSON/CSV report.

Built for SOC analysts, incident responders, threat hunters, and anyone who wants fast, reliable IOC enrichment without leaving the shell.

<table>
<tr>
<td width="50%" valign="top">

**Why ThreatLens**
- One command instead of five browser tabs
- Auto-extracts IOCs straight out of raw logs
- A single failing/rate-limited API never blocks the rest
- Works entirely on free API tiers
- Local SQLite cache — repeated lookups are instant
- Request budget cap prevents runaway API spend

</td>
<td width="50%" valign="top">

**Not for**
- Real-time/streaming detection pipelines
- Paid/enterprise-only intel feeds
- Replacing a full SIEM or SOAR platform

</td>
</tr>
</table>

---

## ✨ Features

| Feature | Details |
|---|---|
| 🎯 **IOC Types** | IP, Domain, URL, File Hash (MD5 / SHA1 / SHA256), CVE |
| 🔌 **Integrated APIs** | AbuseIPDB, VirusTotal, AlienVault OTX, Shodan, URLScan.io, NVD |
| 📄 **Log Parsing** | Automatically extracts every IOC type from any log or text file |
| 📊 **Reports** | Excel (color-coded), JSON, CSV |
| 💾 **Local Cache** | SQLite cache with configurable TTL — skip re-querying known IOCs |
| 🛡️ **Security** | Redirect blocking, host allow-listing, API-key redaction in logs, spreadsheet-formula neutralisation |
| 🔒 **Lockfile** | `requirements.lock` with SHA-256 hashes for reproducible installs |
| 💻 **CLI Experience** | Rich progress bars, colored tables, and a clean verdict summary |
| 🧩 **Architecture** | Modular enrichers, typed models, strict separation of concerns |
| ✅ **Tested** | 60 unit & integration tests with `pytest`; CI via GitHub Actions |
| ⚡ **Resilient** | One failing API never blocks the others — errors are isolated and logged |

---

## 🚀 Quick Start

```bash
# 1. Clone & install
git clone https://github.com/AbdaullahAG/threatlens.git
cd threatlens
pip install -r requirements.txt

# 2. Configure your API keys
cp config/keys.env.example config/keys.env
# → edit config/keys.env and fill in your keys

# 3. Run your first scan
python main.py -i 45.33.32.156
```

> 💡 **NVD (CVE lookups) works out of the box with no API key.** Every other API offers a free tier that takes under 2 minutes to sign up for — see [API Keys](#-api-keys) below.

### Reproducible install (with locked dependencies)

```bash
pip install --require-hashes -r requirements.lock
```

---

## 🧰 Usage

<table>
<tr><td>

```bash
# Investigate a single IP
python main.py -i 45.33.32.156
```

</td><td>Basic single-IOC lookup</td></tr>
<tr><td>

```bash
# Investigate multiple IOC types at once
python main.py -i 45.33.32.156 -d malware.example.com \
  -s d41d8cd98f00b204e9800998ecf8427e -c CVE-2021-44228
```

</td><td>Mix and match IOC types in one run</td></tr>
<tr><td>

```bash
# Parse a log file — all IOCs auto-extracted
python main.py --file /var/log/apache2/access.log
```

</td><td>Bulk investigate straight from raw logs</td></tr>
<tr><td>

```bash
# Output JSON instead of Excel
python main.py -i 8.8.8.8 --format json
```

</td><td>Machine-readable output for pipelines</td></tr>
<tr><td>

```bash
# Use only specific APIs
python main.py -i 8.8.8.8 --apis abuseipdb virustotal
```

</td><td>Restrict enrichment to selected sources</td></tr>
<tr><td>

```bash
# Generate every report format at once
python main.py --file access.log --format all
```

</td><td>Excel + JSON + CSV in a single run</td></tr>
<tr><td>

```bash
# Lookup a CVE — no API key needed
python main.py -c CVE-2021-44228 --apis nvd --format json
```

</td><td>CVE enrichment via NIST NVD (free, no key)</td></tr>
<tr><td>

```bash
# Verbose / debug mode
python main.py -i 8.8.8.8 -v
```

</td><td>Full request/response logging for troubleshooting</td></tr>
</table>

<details>
<summary><b>See all CLI flags</b></summary>
<br>

| Flag | Description |
|---|---|
| `-i, --ip` | IP address(es) to investigate |
| `-d, --domain` | Domain(s) to investigate |
| `-s, --hash` | File hash(es) — MD5 / SHA1 / SHA256 |
| `-c, --cve` | CVE ID(s), e.g. `CVE-2021-44228` |
| `--file` | Path to a log/text file to auto-extract IOCs from |
| `--apis` | Restrict enrichment to a specific set of APIs |
| `--format` | Output format: `excel` (default) \| `json` \| `csv` \| `all` |
| `--output` | Directory to save reports (default: `./output`) |
| `--no-report` | Print results to terminal only, skip saving a file |
| `--cache-path` | SQLite path for local cache (default: `.threatlens/investigations.db`) |
| `--cache-ttl` | Cache lifetime in seconds (default: 3600) |
| `--no-cache` | Bypass the local cache entirely |
| `--max-requests` | Cap on external API calls per run (default: 250) |
| `--max-iocs` | Maximum unique IOCs per run (default: 1000) |
| `--allow-private-iocs` | Allow private/loopback IPs (disabled by default) |
| `--delay` | Delay between API calls, for rate-limit tuning |
| `-v, --verbose` | Enable debug logging |

</details>

---

## 🏗️ Architecture

```
threat_intel_tool/
├── main.py                      # CLI entry point & argument parser
├── requirements.txt             # Runtime dependencies
├── requirements-dev.txt         # Dev/CI tooling (ruff, bandit, pip-audit, pip-tools)
├── requirements.lock            # Pinned lockfile with SHA-256 hashes
├── pytest.ini                   # pytest configuration (marks, etc.)
├── config/
│   └── keys.env                 # API keys (copy from keys.env.example)
├── output/                      # Generated reports land here
├── src/
│   ├── engine.py                # Main orchestrator (collect → enrich → report)
│   ├── models.py                # IOC & EnrichmentResult dataclasses
│   ├── storage.py               # SQLite cache & investigation history
│   ├── parsers/
│   │   └── ioc_parser.py        # Regex-based IOC extractor with validation
│   ├── enrichers/
│   │   ├── base.py              # Abstract base — safe HTTP client (redirect-block, budget, retry)
│   │   ├── registry.py          # Enricher dispatcher
│   │   ├── abuseipdb.py         # AbuseIPDB      (IP)
│   │   ├── virustotal.py        # VirusTotal     (IP / Domain / URL / Hash)
│   │   ├── otx.py               # AlienVault OTX (IP / Domain / URL / Hash)
│   │   ├── shodan.py            # Shodan         (IP)
│   │   ├── urlscan.py           # URLScan.io     (URL / Domain)
│   │   └── nvd.py               # NVD / NIST     (CVE — no key required)
│   ├── reporters/
│   │   ├── excel_reporter.py    # Color-coded Excel reports
│   │   ├── other_reporters.py   # JSON & CSV output
│   │   └── terminal_display.py  # Rich terminal tables
│   └── utils/
│       ├── config.py            # API key loader & runtime config
│       ├── logger.py            # Rich logging setup
│       ├── banner.py            # ASCII banner
│       ├── quota.py             # Per-run request budget (thread-safe)
│       └── security.py         # IOC validation, formula neutralisation, secret redaction
└── tests/
    ├── conftest.py              # pytest fixtures & --run-e2e flag
    ├── test_core.py             # IOC parser, verdict logic, cache round-trip (34 tests)
    ├── test_enrichers.py        # BaseEnricher HTTP edge-cases — mock only (9 tests)
    ├── test_reporters.py        # Excel/CSV formula protection + SQLite integration (17 tests)
    └── test_cli_e2e.py          # Full CLI run against real NVD API (opt-in, --run-e2e)
```

**Design principles**

- **Pluggable enrichers** — adding a new intel source only requires a new file in `src/enrichers/` that subclasses `BaseEnricher`. No changes needed elsewhere.
- **Typed IOCs** — IOC types are enums, not raw strings, catching mistakes at development time instead of runtime.
- **Safe HTTP client** — `BaseEnricher.get()` enforces HTTPS-only, host allow-listing, redirect blocking, 429/Retry-After handling, and request budget capping in one place.
- **CI/CD-friendly config** — keys are read from `config/keys.env` with a fallback to system environment variables.
- **Per-enricher rate limiting** — configurable delay (`--delay`) keeps you within each API's free-tier limits.
- **Fault isolation** — every enricher error is caught, logged, and stored in `result.errors`; a single failing API never brings down the whole scan.
- **Spreadsheet safety** — all values written to Excel and CSV are neutralised against formula-injection (`=`, `+`, `-`, `@` prefixes).

---

## 🔑 API Keys

| Provider | Sign Up | Free Tier |
|---|---|---|
| [AbuseIPDB](https://www.abuseipdb.com/register) | Free | 1,000 checks/day |
| [VirusTotal](https://www.virustotal.com/gui/join-us) | Free | 4 req/min · 500 req/day |
| [AlienVault OTX](https://otx.alienvault.com) | Free | Unlimited (public feed) |
| [Shodan](https://account.shodan.io/register) | Free | Limited lookups |
| [URLScan.io](https://urlscan.io/user/signup) | Free | 5,000 req/day (search is free) |
| [NVD / NIST](https://nvd.nist.gov/developers/request-an-api-key) | Optional | No key required |

---

## 🧪 Testing

```bash
# Run all unit and integration tests (no network required)
pytest tests/ -v --ignore=tests/test_cli_e2e.py

# With coverage report
pytest tests/ -v --ignore=tests/test_cli_e2e.py --cov=src --cov-report=term-missing

# Run the end-to-end CLI test (makes a real NVD request)
pytest tests/test_cli_e2e.py --run-e2e -v
```

### What's tested

| Test file | Coverage |
|---|---|
| `test_core.py` | IOC parser (all types + edge cases), verdict logic, SQLite cache round-trip |
| `test_enrichers.py` | `BaseEnricher.get()` — redirect blocking, budget exhaustion, 429+Retry-After, API-key redaction in logs, non-JSON response, invalid JSON, host allow-list, HTTP scheme block |
| `test_reporters.py` | Excel & CSV formula-injection neutralisation (7 prefix variants), numeric passthrough, SQLite TTL expiry, upsert, investigation recording |
| `test_cli_e2e.py` | Full subprocess run: `python main.py -c CVE-2021-44228 --apis nvd --format json` → exit 0, valid JSON, correct verdict |

---

## 🔐 Security

| Control | Implementation |
|---|---|
| HTTPS-only | `BaseEnricher.get()` rejects any non-`https://` URL before making a request |
| Host allow-list | Each enricher declares `allowed_hosts`; requests to unknown hosts are silently dropped |
| Redirect blocking | All requests use `allow_redirects=False` |
| 429 / Retry-After | Single automatic retry respecting the `Retry-After` header (capped at 15 s) |
| Request budget | `--max-requests` hard-caps total API calls per run |
| API-key redaction | Exceptions and log lines have raw key values replaced with `[REDACTED]` |
| Formula injection | All Excel and CSV cell values are sanitised with `spreadsheet_value()` |
| IOC validation | Every CLI-supplied IOC is validated and normalised before enrichment |
| Private IP guard | Private/loopback addresses are rejected by default (`--allow-private-iocs` to override) |
| Dependency audit | `pip-audit` runs in CI; `requirements.lock` pins all hashes for reproducible installs |

---

## 📊 Sample Output

**Terminal:**

```
╭──────────────────────────── IOC Collection ─────────────────────────────╮
│ Found 4 IOCs to investigate                                              │
│   CVE: 1  Domain: 1  Hash: 1  IP: 1                                     │
╰──────────────────────────────────────────────────────────────────────────╯
✓ Active APIs: abuseipdb, virustotal, otx, shodan, urlscan, nvd

🌐 IP Address Results
┌─────────────────┬──────────────┬──────────┬─────────┬────────────────────┐
│ IP Address      │ Verdict      │ Abuse %  │ Country │ ISP / Org          │
├─────────────────┼──────────────┼──────────┼─────────┼────────────────────┤
│ 45.33.32.156    │ Suspicious   │ 42       │ US      │ Linode             │
└─────────────────┴──────────────┴──────────┴─────────┴────────────────────┘

⚠️  CVE Results
┌──────────────────┬──────────┬──────┬──────────────┐
│ CVE ID           │ Severity │ CVSS │ Published    │
├──────────────────┼──────────┼──────┼──────────────┤
│ CVE-2021-44228   │ Critical │ 10.0 │ 2021-12-10   │
└──────────────────┴──────────┴──────┴──────────────┘
```

**Excel Report:** Multi-sheet workbook with color-coded verdicts (🔴 malicious · 🟡 suspicious · 🟢 clean), saved to `output/ThreatLens_Report_<timestamp>.xlsx`

---

## 🖼️ Screenshots

<p align="center">
  <img src="./screenshots/Screenshot 2026-04-26 223347.png" width="45%" alt="IP Usage">
  <img src="./screenshots/Screenshot 2026-04-26 223543.png" width="45%" alt="Combo lookup #2">
  <img src="./screenshots/Screenshot 2026-04-26 223602.png" width="45%" alt="Combo lookup #1">
  <img src="./screenshots/Screenshot 2026-04-26 223650.png" width="45%" alt="Clean IP verdict">
  <img src="./screenshots/Screenshot 2026-04-26 223744.png" width="45%" alt="Malicious and safe IP comparison">
  <img src="./screenshots/Screenshot 2026-04-26 224246.png" width="45%" alt="Hash lookup">
</p>

---

## 🗺️ Roadmap

- [x] Local SQLite cache with TTL
- [x] Per-run request budget
- [x] IOC validation & private-IP guard
- [x] Spreadsheet formula-injection protection
- [x] API-key redaction in logs
- [x] Pinned lockfile with SHA-256 hashes
- [x] CI pipeline (GitHub Actions)
- [ ] Async/parallel enrichment for faster multi-IOC scans
- [ ] Optional Docker image
- [ ] STIX/TAXII export format
- [ ] Web dashboard (read-only) for report browsing
- [ ] Additional enrichers (GreyNoise, IPQualityScore)

Have an idea? [Open an issue](../../issues) — contributions and suggestions are welcome.

---

## 🤝 Contributing

Contributions are welcome and appreciated!

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Add tests for any new behavior
4. Make sure `pytest tests/ -v --ignore=tests/test_cli_e2e.py` passes and `ruff check .` is clean
5. Open a pull request with a clear description of the change

New enrichers, bug fixes, documentation improvements, and test coverage are all great first contributions — see [Architecture](#️-architecture) for how enrichers are structured.

---

## 📄 License

This project is licensed under the **[PolyForm Noncommercial License 1.0.0](LICENSE)**.

You're free to use, study, modify, and share this code for personal, educational, or research purposes. **Commercial use is not permitted** without prior written permission from the author (`Abd.moh9999@yahoo.com`).

---

## ⚠️ Legal Disclaimer

This tool is intended for **educational and authorized security testing purposes only**. The user is solely responsible for complying with the terms of service of the integrated APIs and all applicable laws. The author assumes no liability and is not responsible for any misuse, illegal activity, or damage caused by this program.

---

<div align="center">

If ThreatLens saved you time, consider giving it a ⭐ — it helps others discover the project.

</div>
