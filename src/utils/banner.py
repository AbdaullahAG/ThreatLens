"""
Banner — printed at startup.
"""

from rich.console import Console
from rich.text import Text
from rich.panel import Panel

console = Console()

BANNER = r"""
 _____ _                    _   _
|_   _| |__  _ __ ___  __ _| |_| |    ___ _ __  ___
  | | | '_ \| '__/ _ \/ _` | __| |   / _ \ '_ \/ __|
  | | | | | | | |  __/ (_| | |_| |__|  __/ | | \__ \
  |_| |_| |_|_|  \___|\__,_|\__|_____\___|_| |_|___/
"""


def print_banner():
    text = Text(BANNER, style="bold cyan")
    subtitle = Text(
        "  Professional Multi-Source Threat Intelligence Enricher  v2.0.0\n"
        "  APIs: AbuseIPDB • VirusTotal • AlienVault OTX • Shodan • URLScan • NVD",
        style="dim white",
    )
    console.print(text)
    console.print(subtitle)
    console.print()
