#!/usr/bin/env python3
"""
ThreatLens - Professional Threat Intelligence CLI Tool
Author: Threat Intel Project
Version: 2.0.0
"""

import sys
import argparse
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

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
        help="Print results to terminal only, do not save a file",
    )

    # --- API Selection ---
    api_group = parser.add_argument_group("API Selection")
    api_group.add_argument(
        "--apis",
        nargs="+",
        choices=["abuseipdb", "virustotal", "otx", "shodan", "urlscan", "nvd"],
        metavar="API",
        help="Limit enrichment to specific APIs (default: all configured)",
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
        version="ThreatLens v2.0.0",
    )

    return parser 


def validate_args(args: argparse.Namespace) -> bool:
    """Ensure at least one IOC source is provided."""
    has_input = any([args.ip, args.domain, args.hash, args.cve, args.file])
    if not has_input:
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
    return True


def main():
    parser = build_parser()
    args = parser.parse_args()

    # Print banner
    print_banner()

    # Validate
    if not validate_args(args):
        sys.exit(1)

    # Setup logger
    logger = setup_logger(verbose=args.verbose)

    # Load config
    config = Config(config_path=args.config, timeout=args.timeout, delay=args.delay)

    # Run engine
    engine = ThreatLensEngine(config=config, logger=logger, args=args)
    success = engine.run()

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
