# 🔍 ThreatLens v2.0

> **Professional Multi-Source Threat Intelligence CLI Tool**  
>Investigate IPs, domains, hashes, and CVEs across 6 free threat intel APIs — without switching between browser tabs.
---

## ✨ Features

| Feature | Details |
|---|---|
| **IOC Types** | IP, Domain, URL, File Hash (MD5/SHA1/SHA256), CVE |
| **APIs** | AbuseIPDB, VirusTotal, AlienVault OTX, Shodan, URLScan.io, NVD |
| **Log Parsing** | Auto-extracts all IOC types from any log/text file |
| **Reports** | Excel (color-coded), JSON, CSV |
| **CLI** | Rich progress bars, colored tables, verdict summary |
| **Architecture** | Modular enrichers, typed models, clean separation of concerns |
| **Tests** | Unit tests with pytest |

---

## 📁 Project Structure

```
threat_intel_tool/
├── main.py                    # CLI entry point
├── requirements.txt
├── config/
│   └── keys.env               # API keys (copy and fill in)
├── output/                    # Reports saved here
├── src/
│   ├── engine.py              # Main orchestrator
│   ├── models.py              # IOC & EnrichmentResult dataclasses
│   ├── parsers/
│   │   └── ioc_parser.py      # Regex-based IOC extractor
│   ├── enrichers/
│   │   ├── base.py            # Abstract base class
│   │   ├── registry.py        # Enricher dispatcher
│   │   ├── abuseipdb.py       # AbuseIPDB (IP)
│   │   ├── virustotal.py      # VirusTotal (IP/Domain/URL/Hash)
│   │   ├── otx.py             # AlienVault OTX (IP/Domain/URL/Hash)
│   │   ├── shodan.py          # Shodan (IP)
│   │   ├── urlscan.py         # URLScan.io (URL/Domain)
│   │   └── nvd.py             # NVD/NIST (CVE) — free, no key needed
│   ├── reporters/
│   │   ├── excel_reporter.py  # Professional color-coded Excel
│   │   ├── other_reporters.py # JSON & CSV
│   │   └── terminal_display.py# Rich terminal tables
│   └── utils/
│       ├── config.py          # API key loader
│       ├── logger.py          # Rich logging
│       └── banner.py          # ASCII banner
└── tests/
    └── test_core.py           # Unit tests
```

---

## 🚀 Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure API keys

```bash
cp config/keys.env config/keys.env   # already there
# Edit config/keys.env and fill in your API keys
```

> **NVD (CVE lookups) works without any key.** All other APIs have free tiers — sign up takes < 2 minutes each.

### 3. Run

```bash
# Investigate a single IP
python main.py -i 45.33.32.156

# Investigate multiple IOC types at once
python main.py -i 45.33.32.156 -d malware.example.com -s d41d8cd98f00b204e9800998ecf8427e -c CVE-2021-44228

# Parse a log file — all IOCs auto-extracted
python main.py --file /var/log/apache2/access.log

# Output JSON instead of Excel
python main.py -i 8.8.8.8 --format json

# Use only specific APIs
python main.py -i 8.8.8.8 --apis abuseipdb virustotal

# All formats at once
python main.py --file access.log --format all

# Verbose/debug mode
python main.py -i 8.8.8.8 -v
```

---

## 🧪 Running Tests

```bash
pytest tests/ -v
# With coverage
pytest tests/ -v --cov=src --cov-report=term-missing
```

---
## 🏗️ Architecture Notes

- **Enrichers** are fully independent — adding a new API requires only a new file in `src/enrichers/` that inherits from `BaseEnricher`.
- **IOC types** are typed enums, not strings — prevents bugs.
- **Config** reads from `config/keys.env` with system environment variable fallback — CI/CD friendly.
- **Rate limiting** is handled per-enricher with configurable delay (`--delay`).
- **All errors** are caught, logged, and stored in `result.errors` — one failing API never stops the others.
---

## 🔑 API Keys — Where to Get Them

| API | Sign Up | Free Tier |
|---|---|---|
| [AbuseIPDB](https://www.abuseipdb.com/register) | Free | 1,000 checks/day |
| [VirusTotal](https://www.virustotal.com/gui/join-us) | Free | 4 req/min, 500/day |
| [AlienVault OTX](https://otx.alienvault.com) | Free | Unlimited public |
| [Shodan](https://account.shodan.io/register) | Free | Limited lookups |
| [URLScan.io](https://urlscan.io/user/signup) | Free | 5,000/day (search free) |
| [NVD/NIST](https://nvd.nist.gov/developers/request-an-api-key) | Free | No key needed |

---

## 📊 Output Example

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

**Excel report:** Multi-sheet workbook with color-coded verdicts (red = malicious, yellow = suspicious, green = clean), saved to `output/ThreatLens_Report_<timestamp>.xlsx`

---

## 📄 License

MIT License — free for personal, academic, and commercial use.
