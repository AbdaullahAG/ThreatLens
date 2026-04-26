"""
Terminal Display — Rich-powered live output for CLI mode.
"""

from __future__ import annotations

from typing import List

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.columns import Columns
from rich import box

from src.models import EnrichmentResult, IOCType

console = Console()

VERDICT_STYLES = {
    "Malicious": "bold red",
    "Suspicious": "bold yellow",
    "Clean":      "bold green",
    "Unknown":    "dim",
    "Critical":   "bold red",
    "High":       "bold orange1",
    "Medium":     "bold yellow",
    "Low":        "bold green",
}


def display_results(results: List[EnrichmentResult]):
    """Print all results to the terminal using Rich tables."""
    if not results:
        console.print("[yellow]No results to display.[/]")
        return

    # Split by type
    ips      = [r for r in results if r.ioc.ioc_type == IOCType.IP]
    domains  = [r for r in results if r.ioc.ioc_type in (IOCType.DOMAIN, IOCType.URL)]
    hashes   = [r for r in results if r.ioc.ioc_type == IOCType.HASH]
    cves     = [r for r in results if r.ioc.ioc_type == IOCType.CVE]

    if ips:
        console.print(_build_ip_table(ips))
    if domains:
        console.print(_build_domain_table(domains))
    if hashes:
        console.print(_build_hash_table(hashes))
    if cves:
        console.print(_build_cve_table(cves))

    _print_summary(results)


def _verdict_text(verdict: str) -> Text:
    style = VERDICT_STYLES.get(verdict, "")
    return Text(verdict, style=style)


def _build_ip_table(results: List[EnrichmentResult]) -> Table:
    t = Table(
        title="🌐  IP Address Results",
        box=box.ROUNDED,
        show_lines=True,
        border_style="cyan",
        header_style="bold white on blue",
    )
    t.add_column("IP Address",      style="cyan",    min_width=16)
    t.add_column("Verdict",         min_width=12,    justify="center")
    t.add_column("Abuse %",         justify="right",  min_width=8)
    t.add_column("Country",         min_width=8)
    t.add_column("ISP / Org",       min_width=20)
    t.add_column("Reports",         justify="right",  min_width=8)
    t.add_column("Open Ports",      min_width=18)
    t.add_column("Shodan Vulns",    min_width=16)

    for r in results:
        t.add_row(
            r.ioc.value,
            _verdict_text(r.verdict),
            str(r.abuse_score),
            r.country or "—",
            r.organization or r.isp or "—",
            str(r.total_reports),
            ", ".join(str(p) for p in r.open_ports[:6]) or "—",
            ", ".join(r.shodan_vulns[:3]) or "—",
        )
    return t


def _build_domain_table(results: List[EnrichmentResult]) -> Table:
    t = Table(
        title="🔗  Domain & URL Results",
        box=box.ROUNDED,
        show_lines=True,
        border_style="magenta",
        header_style="bold white on blue",
    )
    t.add_column("IOC",             style="magenta", min_width=32, no_wrap=False)
    t.add_column("Type",            min_width=8)
    t.add_column("Verdict",         min_width=12,    justify="center")
    t.add_column("VT Malicious",    justify="right",  min_width=12)
    t.add_column("VT Suspicious",   justify="right",  min_width=13)
    t.add_column("URLScan",         min_width=12,    justify="center")
    t.add_column("Categories",      min_width=20)

    for r in results:
        t.add_row(
            r.ioc.value[:60] + ("…" if len(r.ioc.value) > 60 else ""),
            r.ioc.ioc_type.value,
            _verdict_text(r.verdict),
            str(r.malicious_votes),
            str(r.suspicious_votes),
            r.urlscan_verdict or "—",
            ", ".join(r.categories[:3]) or "—",
        )
    return t


def _build_hash_table(results: List[EnrichmentResult]) -> Table:
    t = Table(
        title="🔑  File Hash Results",
        box=box.ROUNDED,
        show_lines=True,
        border_style="yellow",
        header_style="bold white on blue",
    )
    t.add_column("Hash",            style="yellow",  min_width=20, no_wrap=False)
    t.add_column("Verdict",         min_width=12,    justify="center")
    t.add_column("File Name",       min_width=20)
    t.add_column("File Type",       min_width=14)
    t.add_column("Size (bytes)",    justify="right",  min_width=12)
    t.add_column("Detections",      justify="center", min_width=14)
    t.add_column("Tags",            min_width=20)

    for r in results:
        det = f"{r.positives}/{r.total_scanners}" if r.total_scanners else "—"
        t.add_row(
            r.ioc.value[:20] + "…" if len(r.ioc.value) > 20 else r.ioc.value,
            _verdict_text(r.verdict),
            r.file_name or "—",
            r.file_type or "—",
            str(r.file_size) if r.file_size else "—",
            det,
            ", ".join(r.tags[:3]) or "—",
        )
    return t


def _build_cve_table(results: List[EnrichmentResult]) -> Table:
    t = Table(
        title="⚠️   CVE Results",
        box=box.ROUNDED,
        show_lines=True,
        border_style="red",
        header_style="bold white on blue",
    )
    t.add_column("CVE ID",          style="bold red", min_width=18)
    t.add_column("Severity",        min_width=10,    justify="center")
    t.add_column("CVSS",            justify="right",  min_width=8)
    t.add_column("Published",       min_width=12)
    t.add_column("Affected (sample)", min_width=30)
    t.add_column("Description",     min_width=50,    no_wrap=False)

    for r in results:
        desc = (r.cve_description or "—")[:120] + ("…" if r.cve_description and len(r.cve_description) > 120 else "")
        t.add_row(
            r.ioc.value,
            _verdict_text(r.verdict),
            str(r.cvss_score) if r.cvss_score else "—",
            r.published_date or "—",
            "; ".join(r.affected_products[:3]) or "—",
            desc,
        )
    return t


def _print_summary(results: List[EnrichmentResult]):
    total     = len(results)
    malicious = sum(1 for r in results if r.verdict in ("Malicious", "Critical"))
    suspicious = sum(1 for r in results if r.verdict in ("Suspicious", "High", "Medium"))
    clean     = sum(1 for r in results if r.verdict in ("Clean", "Low"))
    unknown   = total - malicious - suspicious - clean

    panels = [
        Panel(f"[bold]{total}[/]",      title="Total IOCs",  border_style="blue"),
        Panel(f"[bold red]{malicious}[/]",  title="Malicious",   border_style="red"),
        Panel(f"[bold yellow]{suspicious}[/]", title="Suspicious", border_style="yellow"),
        Panel(f"[bold green]{clean}[/]", title="Clean",       border_style="green"),
        Panel(f"[dim]{unknown}[/]",      title="Unknown",     border_style="grey50"),
    ]
    console.print()
    console.print(Columns(panels))
    console.print()
