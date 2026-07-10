"""
ThreatLens Engine — main orchestrator.
Ties together: IOC parsing → enrichment → display → reporting.
""" 

from __future__ import annotations
 
import argparse
import logging
from typing import List

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.panel import Panel

from src.models import IOC, EnrichmentResult
from src.parsers.ioc_parser import IOCParser
from src.enrichers.registry import build_enrichers, enrich_ioc
from src.reporters.terminal_display import display_results
from src.reporters.excel_reporter import ExcelReporter
from src.reporters.other_reporters import JSONReporter, CSVReporter
from src.utils.config import Config

console = Console()


class ThreatLensEngine:

    def __init__(self, config: Config, logger: logging.Logger, args: argparse.Namespace):
        self.config = config
        self.logger = logger
        self.args = args

    def run(self) -> bool:
        try:
            # 1. Collect IOCs
            iocs = self._collect_iocs()
            if not iocs:
                console.print("[yellow]⚠  No valid IOCs found to investigate.[/]")
                return False

            console.print(
                Panel(
                    f"[bold]Found [cyan]{len(iocs)}[/] IOCs to investigate[/]\n"
                    + self._ioc_type_summary(iocs),
                    title="[bold blue]IOC Collection[/]",
                    border_style="blue",
                )
            )

            # 2. Build enrichers
            enrichers = build_enrichers(self.config, selected_apis=self.args.apis)
            if not enrichers:
                console.print(
                    "[red]✗ No enrichers available.[/] "
                    "Please configure API keys in [cyan]config/keys.env[/]"
                )
                return False

            api_names = ", ".join(e.name for e in enrichers)
            console.print(f"[green]✓[/] Active APIs: [cyan]{api_names}[/]\n")

            # 3. Enrich with progress bar
            results = self._run_enrichment(iocs, enrichers)

            # 4. Terminal display
            if results:
                display_results(results)

            # 5. Save reports
            if not self.args.no_report:
                self._save_reports(results)

            return True

        except KeyboardInterrupt:
            console.print("\n[yellow]⚠  Interrupted by user.[/]")
            return False
        except Exception as e:
            self.logger.exception(f"Engine error: {e}")
            return False

    def _collect_iocs(self) -> List[IOC]:
        """Gather IOCs from CLI arguments and/or log file."""
        iocs: List[IOC] = []
        parser = IOCParser()

        # Explicit CLI inputs
        explicit = IOCParser.from_args(
            ips=self.args.ip,
            domains=self.args.domain,
            hashes=self.args.hash,
            cves=self.args.cve,
        )
        iocs.extend(explicit)

        # Log file
        if self.args.file:
            console.print(f"[blue]📂 Parsing log file:[/] {self.args.file}")
            parse_result = parser.parse_file(self.args.file)

            # Print stats
            s = parse_result.stats
            console.print(
                f"  Extracted → "
                f"IPs: [cyan]{s['ip']}[/]  "
                f"Domains: [cyan]{s['domain']}[/]  "
                f"URLs: [cyan]{s['url']}[/]  "
                f"Hashes: [cyan]{s['hash']}[/]  "
                f"CVEs: [cyan]{s['cve']}[/]  "
                f"[dim](skipped {s['ignored_private_ips']} private IPs)[/]"
            )
            iocs.extend(parse_result.iocs)

        # Deduplicate by value+type
        seen: set[str] = set()
        unique: List[IOC] = []
        for ioc in iocs:
            key = f"{ioc.ioc_type}:{ioc.value.lower()}"
            if key not in seen:
                seen.add(key)
                unique.append(ioc)

        return unique

    def _run_enrichment(
        self, iocs: List[IOC], enrichers: list
    ) -> List[EnrichmentResult]:
        results: List[EnrichmentResult] = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("({task.completed}/{task.total})"),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        ) as progress:
            task = progress.add_task("[cyan]Enriching IOCs...", total=len(iocs))

            for ioc in iocs:
                progress.update(
                    task,
                    description=f"[cyan]Enriching [bold]{ioc.ioc_type.value}[/]: {ioc.value[:40]}",
                )
                result = enrich_ioc(ioc, enrichers)
                results.append(result)
                progress.advance(task)

        return results

    def _save_reports(self, results: List[EnrichmentResult]):
        fmt = self.args.format
        out = self.args.output
        saved = []

        try:
            if fmt in ("excel", "all"):
                path = ExcelReporter().generate(results, output_dir=out)
                saved.append(("Excel", path))

            if fmt in ("json", "all"):
                path = JSONReporter().generate(results, output_dir=out)
                saved.append(("JSON", path))

            if fmt in ("csv", "all"):
                path = CSVReporter().generate(results, output_dir=out)
                saved.append(("CSV", path))

            console.print()
            for fmt_name, path in saved:
                console.print(f"[green]✓ {fmt_name} report saved:[/] [bold]{path}[/]")

        except Exception as e:
            self.logger.error(f"Failed to save report: {e}")

    @staticmethod
    def _ioc_type_summary(iocs: List[IOC]) -> str:
        from src.models import IOCType
        from collections import Counter
        counts = Counter(i.ioc_type.value for i in iocs)
        return "  " + "  ".join(f"[cyan]{t}[/]: {c}" for t, c in sorted(counts.items()))
