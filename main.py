#!/usr/bin/env python3
"""
ThreatLens - Professional Threat Intelligence CLI Tool
Author: Threat Intel Project
Version: 2.2.0
"""

import sys
import argparse
from pathlib import Path
from rich.console import Console
from rich.panel import Panel

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from src.engine import ThreatLensEngine
from src.utils.logger import setup_logger
from src.utils.config import Config
from src.utils.banner import print_banner

console = Console()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="threatlens",
        description="ThreatLens — Professional Multi-Source Threat Intelligence Enricher",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a single IP
  python main.py -i 8.8.8.8

  # Scan multiple IOCs (IP, domain, hash, CVE)
  python main.py -i 8.8.8.8 -d example.com -s abc123def456 -c CVE-2021-44228

  # Scan from a log file
  python main.py --file /var/log/access.log

  # Output as JSON instead of Excel
  python main.py -i 45.33.32.156 --format json

  # Use specific APIs only
  python main.py -i 45.33.32.156 --apis abuseipdb virustotal

  # Set custom output directory
  python main.py --file access.log --output /tmp/reports

  # Import an asset inventory and get CVE decision cards
  python main.py -c CVE-2021-44228 --import-assets assets.csv --decision-cards

  # Parse a Suricata eve.json and export to Splunk, with an evidence pack
  python main.py --file eve.json --log-format suricata --export splunk --evidence-pack
        """,
    )

    # --- IOC Input Group ---
    ioc_group = parser.add_argument_group("IOC Inputs")
    ioc_group.add_argument(
        "-i", "--ip",
        nargs="+",
        metavar="IP",
        help="One or more IP addresses to investigate",
    )
    ioc_group.add_argument(
        "--allow-private-iocs",
        action="store_true",
        help="Allow private, loopback, and reserved IP observables (they may be sent to external providers)",
    )
    ioc_group.add_argument(
        "-d", "--domain",
        nargs="+",
        metavar="DOMAIN",
        help="One or more domains or URLs to investigate",
    )
    ioc_group.add_argument(
        "-s", "--hash",
        nargs="+",
        metavar="HASH",
        help="One or more file hashes (MD5, SHA1, SHA256)",
    )
    ioc_group.add_argument(
        "-c", "--cve",
        nargs="+",
        metavar="CVE",
        help="One or more CVE IDs (e.g. CVE-2021-44228)",
    )
    ioc_group.add_argument(
        "-f", "--file",
        metavar="PATH",
        help="Path to a log file — IPs, domains, hashes will be auto-extracted",
    )
    ioc_group.add_argument(
        "--log-format",
        choices=["auto", "text", "zeek", "suricata", "sysmon", "jsonl"],
        default="auto",
        help="Format of --file (default: auto-detect from filename/content)",
    )

    # --- Output Options ---
    out_group = parser.add_argument_group("Output Options")
    out_group.add_argument(
        "--format",
        choices=["excel", "json", "csv", "all"],
        default="excel",
        help="Output report format (default: excel)",
    )
    out_group.add_argument(
        "--output",
        metavar="DIR",
        default="output",
        help="Directory to save reports (default: ./output)",
    )
    out_group.add_argument(
        "--no-report",
        action="store_true",
        help="Print results to terminal only; investigation history may still be stored",
    )

    # --- API Selection ---
    api_group = parser.add_argument_group("API Selection")
    api_group.add_argument(
        "--apis",
        nargs="+",
        choices=["abuseipdb", "virustotal", "otx", "shodan", "urlscan", "nvd", "cisa_kev", "epss"],
        metavar="API",
        help="Limit enrichment to specific APIs (default: all configured)",
    )

    # --- Privacy & Watchlist Monitoring (v2.3) ---
    privacy_group = parser.add_argument_group("Privacy & Watchlist Monitoring")
    privacy_group.add_argument(
        "--privacy-mode",
        choices=["standard", "passive", "approved-only", "local-only"],
        default="standard",
        help="Control external enrichment: standard, read-only passive, approved providers only, or local cache only",
    )
    privacy_group.add_argument(
        "--approved-apis",
        nargs="+",
        choices=["abuseipdb", "virustotal", "otx", "shodan", "urlscan", "nvd", "cisa_kev", "epss"],
        metavar="API",
        help="Provider allow-list required with --privacy-mode approved-only",
    )
    privacy_group.add_argument(
        "--privacy-preview",
        action="store_true",
        help="Show sanitized IOC values and external destinations before enrichment",
    )
    privacy_group.add_argument(
        "--watchlist-add",
        action="store_true",
        help="Add the supplied IOCs to the local watchlist",
    )
    privacy_group.add_argument(
        "--watchlist-list",
        action="store_true",
        help="List active local watchlist entries and exit",
    )
    privacy_group.add_argument(
        "--watchlist-remove",
        nargs="+",
        metavar="TYPE:VALUE",
        help="Remove watchlist entries, e.g. IP:8.8.8.8 or URL:https://example.com/a",
    )
    privacy_group.add_argument(
        "--watchlist-scan",
        action="store_true",
        help="Enrich all active watchlist entries and report changes from their last observation",
    )
    privacy_group.add_argument(
        "--watchlist-ttl-days",
        type=int,
        default=90,
        help="Expiry applied when adding IOCs to the watchlist (1-3650 days; default: 90)",
    )

    # --- Local Investigation Memory ---
    history_group = parser.add_argument_group("Local Investigation Memory")
    history_group.add_argument(
        "--history-list",
        action="store_true",
        help="List recent local IOC observations; combine with history filters",
    )
    history_group.add_argument(
        "--history-search",
        metavar="QUERY",
        help="Search saved IOC values and provider names",
    )
    history_group.add_argument(
        "--history-ioc",
        metavar="TYPE:VALUE",
        help="Show an IOC's saved verdict timeline and co-occurring IOCs",
    )
    history_group.add_argument(
        "--history-type",
        choices=["IP", "Domain", "URL", "Hash", "CVE"],
        help="Filter history by IOC type",
    )
    history_group.add_argument(
        "--history-verdict",
        choices=["Malicious", "Suspicious", "Clean", "Unknown", "Critical", "High", "Medium", "Low"],
        help="Filter history by verdict",
    )
    history_group.add_argument(
        "--history-severity",
        choices=["Critical", "High", "Medium", "Low"],
        help="Filter CVE history by severity",
    )
    history_group.add_argument("--history-after", metavar="ISO_DATE", help="Include observations on/after this UTC date")
    history_group.add_argument("--history-before", metavar="ISO_DATE", help="Include observations on/before this UTC date")
    history_group.add_argument(
        "--history-limit", type=int, default=50,
        help="Maximum observations to display/export (1-500; default: 50)",
    )
    history_group.add_argument(
        "--history-delete", metavar="INVESTIGATION_ID",
        help="Delete one saved investigation and its indexed history by UUID",
    )
    history_group.add_argument(
        "--history-prune-days", type=int, metavar="DAYS",
        help="Delete saved investigations older than this many days (1-36500)",
    )
    history_group.add_argument(
        "--history-export", metavar="PATH",
        help="Export matching local history as redacted JSON to a new file",
    )

    # --- Vulnerability & SOC Triage (v2.2) ---
    vuln_group = parser.add_argument_group("Vulnerability & SOC Triage")
    vuln_group.add_argument(
        "--import-assets",
        metavar="CSV_PATH",
        help="Import an asset inventory CSV (hostname/ip, criticality, internet_facing, owner, product) "
             "before scanning; replaces any previously imported inventory",
    )
    vuln_group.add_argument(
        "--decision-cards",
        action="store_true",
        help="Produce a Patch/Isolate/Monitor/Not-affected decision card for every CVE result, "
             "correlated against the imported asset inventory",
    )
    vuln_group.add_argument(
        "--evidence-pack",
        action="store_true",
        help="Package this investigation's results (and decision cards, if any) into a "
             "hash-manifested ZIP evidence pack",
    )

    # --- SIEM Export ---
    export_group = parser.add_argument_group("SIEM Export")
    export_group.add_argument(
        "--export",
        nargs="+",
        choices=["splunk", "elastic", "sentinel"],
        metavar="DEST",
        help="Send results to one or more configured SIEM destinations (opt-in; "
             "credentials/endpoints are read from config/keys.env)",
    )
    export_group.add_argument(
        "--export-insecure-tls",
        action="store_true",
        help="Disable TLS certificate verification for SIEM export (logged loudly; testing only)",
    )

    # --- Config / Misc ---
    misc_group = parser.add_argument_group("Configuration")
    misc_group.add_argument(
        "--config",
        metavar="FILE",
        default="config/keys.env",
        help="Path to API keys config file (default: config/keys.env)",
    )
    misc_group.add_argument(
        "--max-file-size-mb",
        type=int,
        default=10,
        help="Maximum log file size to parse in MiB (default: 10; maximum: 100)",
    )
    misc_group.add_argument(
        "--max-iocs",
        type=int,
        default=1000,
        help="Maximum unique IOCs accepted per run (default: 1000)",
    )
    misc_group.add_argument(
        "--max-requests",
        type=int,
        default=250,
        help="Maximum external API requests per run (default: 250)",
    )
    misc_group.add_argument(
        "--cache-path",
        default=".threatlens/investigations.db",
        help="SQLite path for local cache and investigation history",
    )
    misc_group.add_argument(
        "--cache-ttl",
        type=int,
        default=3600,
        help="Cache lifetime in seconds (default: 3600)",
    )
    misc_group.add_argument(
        "--no-cache",
        action="store_true",
        help="Bypass IOC and provider-feed caches; does not disable investigation history",
    )
    misc_group.add_argument(
        "--no-history",
        action="store_true",
        help="Do not save this run to the local investigation history",
    )
    misc_group.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="HTTP request timeout in seconds (default: 10)",
    )
    misc_group.add_argument(
        "--delay",
        type=float,
        default=0.5,
        help="Delay between API calls in seconds (default: 0.5)",
    )
    misc_group.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose/debug logging",
    )
    misc_group.add_argument(
        "--version",
        action="version",
        version="ThreatLens v2.2.0",
    )

    return parser 


def validate_args(args: argparse.Namespace) -> bool:
    """Ensure at least one IOC source is provided."""
    has_input = any([args.ip, args.domain, args.hash, args.cve, args.file])
    history_actions = [
        bool(getattr(args, "history_list", False)),
        bool(getattr(args, "history_search", None)),
        bool(getattr(args, "history_ioc", None)),
        bool(getattr(args, "history_delete", None)),
        getattr(args, "history_prune_days", None) is not None,
    ]
    history_filters = any(
        getattr(args, name, None) is not None
        for name in ("history_type", "history_verdict", "history_severity", "history_after", "history_before")
    )
    history_requested = any(history_actions) or bool(getattr(args, "history_export", None)) or history_filters
    history_action_count = sum(history_actions)
    if history_action_count > 1:
        console.print("[red]Choose only one history action: list, search, IOC timeline, delete, or prune.[/]")
        return False
    if history_requested and (has_input or getattr(args, "watchlist_add", False) or getattr(args, "watchlist_list", False)
                              or getattr(args, "watchlist_remove", None) or getattr(args, "watchlist_scan", False)):
        console.print("[red]History operations must be run separately from IOC scans and watchlist actions.[/]")
        return False
    if history_requested and not any(history_actions) and not getattr(args, "history_export", None):
        console.print("[red]Use --history-list or --history-search with history filters.[/]")
        return False
    if history_requested and not 1 <= getattr(args, "history_limit", 50) <= 500:
        console.print("[red]--history-limit must be between 1 and 500.[/]")
        return False
    if getattr(args, "history_ioc", None) and (history_filters or getattr(args, "history_export", None)):
        console.print("[red]--history-ioc cannot be combined with search filters or --history-export.[/]")
        return False
    if (getattr(args, "history_delete", None) or getattr(args, "history_prune_days", None) is not None) and (
        getattr(args, "history_export", None) or history_filters or getattr(args, "history_search", None)
        or getattr(args, "history_list", False) or getattr(args, "history_ioc", None)
    ):
        console.print("[red]History filters/exports cannot be combined with deletion or pruning.[/]")
        return False
    if getattr(args, "history_prune_days", None) is not None and not 1 <= args.history_prune_days <= 36_500:
        console.print("[red]--history-prune-days must be between 1 and 36500.[/]")
        return False
    standalone_watchlist_action = bool(
        getattr(args, "watchlist_list", False)
        or getattr(args, "watchlist_remove", None)
        or getattr(args, "watchlist_scan", False)
    )
    if not has_input and not standalone_watchlist_action:
        if history_requested:
            return True
        console.print(
            Panel(
                "[bold red]Error:[/] No IOC provided.\n\n"
                "Use [cyan]-i[/] for IPs, [cyan]-d[/] for domains, "
                "[cyan]-s[/] for hashes, [cyan]-c[/] for CVEs, "
                "or [cyan]-f[/] to parse a log file.\n\n"
                "Run [cyan]python main.py --help[/] for usage.",
                title="[red]Missing Input[/]",
                border_style="red",
            )
        )
        return False
    if getattr(args, "watchlist_list", False) and (
        has_input or getattr(args, "watchlist_remove", None) or getattr(args, "watchlist_scan", False)
    ):
        console.print("[red]--watchlist-list must be used by itself.[/]")
        return False
    if getattr(args, "watchlist_remove", None) and (
        has_input or getattr(args, "watchlist_scan", False) or getattr(args, "watchlist_add", False)
    ):
        console.print("[red]--watchlist-remove must be used without IOC inputs, --watchlist-add, or --watchlist-scan.[/]")
        return False
    if getattr(args, "watchlist_scan", False) and (has_input or getattr(args, "watchlist_add", False)):
        console.print("[red]--watchlist-scan loads its IOCs from the watchlist; do not provide other inputs or --watchlist-add.[/]")
        return False
    return True


def main():
    parser = build_parser()
    args = parser.parse_args()

    # Print banner
    print_banner()

    # Validate
    if not validate_args(args):
        sys.exit(1)

    if args.privacy_mode == "approved-only" and not args.approved_apis:
        parser.error("--privacy-mode approved-only requires --approved-apis")
    if args.approved_apis and args.privacy_mode != "approved-only":
        parser.error("--approved-apis can only be used with --privacy-mode approved-only")
    if args.export and args.privacy_mode != "standard":
        parser.error("--export requires --privacy-mode standard; exporters are separate external destinations")
    if not 1 <= args.watchlist_ttl_days <= 3650:
        parser.error("--watchlist-ttl-days must be between 1 and 3650")

    # Setup logger
    logger = setup_logger(verbose=args.verbose)

    # Load config
    try:
        config = Config(
            config_path=args.config,
            timeout=args.timeout,
            delay=args.delay,
            max_file_bytes=args.max_file_size_mb * 1024 * 1024,
            max_iocs=args.max_iocs,
            max_requests=args.max_requests,
        )
        if args.cache_ttl < 0:
            raise ValueError("cache_ttl must be zero or greater")
    except ValueError as exc:
        parser.error(str(exc))

    # Run engine
    engine = ThreatLensEngine(config=config, logger=logger, args=args)
    success = engine.run()

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
