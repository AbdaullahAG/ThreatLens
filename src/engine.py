"""
ThreatLens Engine — main orchestrator.
Ties together: IOC parsing → enrichment → display → reporting.
""" 

from __future__ import annotations
 
import argparse
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import List

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from src.models import IOC, EnrichmentResult, IOCType
from src.parsers.ioc_parser import IOCParser
from src.enrichers.registry import build_enrichers, enrich_ioc
from src.reporters.terminal_display import display_results
from src.reporters.excel_reporter import ExcelReporter
from src.reporters.other_reporters import JSONReporter, CSVReporter
from src.utils.config import Config
from src.storage import InvestigationStore
from src.utils.quota import RequestBudget
from src.utils.security import (
    IOCValidationError,
    redact_secrets,
    sanitize_ioc_for_external,
    sanitize_result_for_output,
    validate_ioc,
)

console = Console()


class ThreatLensEngine:

    def __init__(self, config: Config, logger: logging.Logger, args: argparse.Namespace):
        self.config = config
        self.logger = logger
        self.args = args
        self.store = InvestigationStore(args.cache_path)
        self.request_budget = RequestBudget(config.max_requests)
        self._watchlist_scan_invalid = False

    def run(self) -> bool:
        try:
            if getattr(self.args, "watchlist_list", False):
                self._display_watchlist()
                return True
            if getattr(self.args, "watchlist_remove", None):
                self._remove_from_watchlist(self.args.watchlist_remove)
                return True

            if getattr(self.args, 'import_assets', None):
                self._import_assets()

            # 1. Collect IOCs
            iocs = self._collect_iocs()
            if not iocs:
                if getattr(self.args, "watchlist_scan", False):
                    if self._watchlist_scan_invalid:
                        return False
                    console.print("[yellow]The local watchlist is empty; nothing to scan.[/]")
                    return True
                console.print("[yellow]⚠  No valid IOCs found to investigate.[/]")
                return False

            if getattr(self.args, "watchlist_add", False):
                expires_at = int(time.time()) + self.args.watchlist_ttl_days * 24 * 60 * 60
                count = self.store.add_watchlist_iocs(iocs, expires_at=expires_at)
                console.print(f"[green]✓ Added/updated {count} IOC(s) in the local watchlist.[/]")

            console.print(
                Panel(
                    f"[bold]Found [cyan]{len(iocs)}[/] IOCs to investigate[/]\n"
                    + self._ioc_type_summary(iocs),
                    title="[bold blue]IOC Collection[/]",
                    border_style="blue",
                )
            )

            # 2. Build enrichers
            privacy_mode = getattr(self.args, "privacy_mode", "standard")
            selected_apis = self.args.apis
            if privacy_mode == "approved-only":
                approved = set(self.args.approved_apis or [])
                selected_apis = sorted(approved if selected_apis is None else approved.intersection(selected_apis))
            enrichers = [] if privacy_mode == "local-only" else build_enrichers(
                self.config,
                selected_apis=selected_apis,
                request_budget=self.request_budget,
                # --no-cache bypasses both per-IOC results and provider feed
                # caches, while leaving investigation history independent.
                store=None if self.args.no_cache else self.store,
            )
            if not enrichers and privacy_mode != "local-only":
                console.print(
                    "[red]✗ No enrichers available for this provider selection.[/] "
                    "Check the approved API list and configured keys in [cyan]config/keys.env[/]."
                )
                return False

            if privacy_mode == "local-only":
                console.print("[yellow]Local-only mode: external provider requests are disabled.[/]")
            else:
                api_names = ", ".join(e.name for e in enrichers)
                console.print(f"[green]✓[/] Active APIs: [cyan]{api_names}[/]\n")

            if getattr(self.args, "privacy_preview", False):
                self._display_privacy_preview(iocs, enrichers, privacy_mode)
            elif any(sanitize_ioc_for_external(ioc).value != ioc.value for ioc in iocs):
                console.print(
                    "[dim]Sensitive URL query parameters are omitted from external lookups; "
                    "the original IOC remains local.[/]"
                )

            # 3. Enrich with progress bar
            results = self._run_enrichment(iocs, enrichers)

            watchlist_changes = self._record_watchlist_observations(
                results, persist=not getattr(self.args, "no_history", False)
            )

            # 4. Terminal display
            if results:
                display_results(results)
            self._display_watchlist_changes(watchlist_changes)

            if getattr(self.args, "no_history", False):
                investigation_id = str(uuid.uuid4())
                console.print("[dim]Investigation history storage disabled for this run.[/]")
            else:
                investigation_id = self.store.record_investigation(results)
                console.print(f"[dim]Investigation recorded locally: {investigation_id}[/]")

            # 5. CVE Decision Cards (optional)
            decision_cards = self._build_decision_cards(results) if getattr(self.args, 'decision_cards', False) else []

            # 6. Save reports
            if not self.args.no_report:
                self._save_reports(results)

            # 7. SIEM export (optional, opt-in)
            if getattr(self.args, 'export', None):
                self._export_results(results)

            # 8. Evidence pack (optional)
            if getattr(self.args, 'evidence_pack', False):
                self._build_evidence_pack(investigation_id, results, decision_cards)

            return True

        except KeyboardInterrupt:
            console.print("\n[yellow]⚠  Interrupted by user.[/]")
            return False
        except Exception as e:
            console.print("[red]✗ Investigation failed. See the application log for a redacted diagnostic.[/]")
            self.logger.error("Engine error: %s", redact_secrets(e, *self.config.secret_values()))
            return False

    def _import_assets(self) -> None:
        """Import an asset inventory CSV, replacing any previous import."""
        from src.assets.importer import AssetImportError, AssetImporter

        console.print("[blue]📋 Importing asset inventory.[/]")
        importer = AssetImporter(
            max_file_bytes=self.config.max_asset_file_bytes,
            max_rows=self.config.max_asset_rows,
        )
        try:
            result = importer.import_file(self.args.import_assets)
        except AssetImportError as exc:
            self.logger.warning("Asset import rejected: %s", redact_secrets(exc, *self.config.secret_values()))
            console.print("[red]✗ Asset import failed validation or could not be read safely.[/]")
            return

        count = self.store.replace_assets(result.assets, source_file=self.args.import_assets)
        note = f" ([yellow]{len(result.skipped_rows)} row(s) skipped[/])" if result.skipped_rows else ""
        console.print(f"[green]✓[/] Imported [cyan]{count}[/] asset(s){note}")
        if result.truncated:
            console.print(
                f"[yellow]⚠ Asset row limit ({self.config.max_asset_rows}) reached; "
                f"remaining rows were skipped.[/]"
            )

    def _display_watchlist(self) -> None:
        entries = self.store.list_watchlist()
        if not entries:
            console.print("[yellow]The local watchlist is empty.[/]")
            return
        table = Table(title="Local IOC Watchlist", show_lines=True)
        table.add_column("Type", style="cyan")
        table.add_column("Value", overflow="fold")
        table.add_column("Added at")
        table.add_column("Expires at")
        for entry in entries:
            expires = (
                datetime.fromtimestamp(entry["expires_at"], timezone.utc).isoformat()
                if entry["expires_at"] else "Never"
            )
            table.add_row(entry["ioc_type"], entry["ioc_value"], entry["added_at"], expires)
        console.print(table)

    def _remove_from_watchlist(self, raw_entries: list[str]) -> None:
        type_map = {ioc_type.value.lower(): ioc_type for ioc_type in IOCType}
        iocs = []
        try:
            for raw in raw_entries:
                kind, separator, value = raw.partition(":")
                ioc_type = type_map.get(kind.strip().lower())
                if not separator or ioc_type is None:
                    raise IOCValidationError(f"watchlist entry must be TYPE:VALUE: {raw}")
                iocs.append(
                    IOC(
                        value=validate_ioc(value, ioc_type, allow_private=True),
                        ioc_type=ioc_type,
                    )
                )
        except IOCValidationError as exc:
            self.logger.warning("Watchlist removal rejected: %s", redact_secrets(exc, *self.config.secret_values()))
            console.print("[red]✗ Watchlist removal rejected; check IOC type and value.[/]")
            return
        removed = self.store.remove_watchlist_iocs(iocs)
        console.print(f"[green]✓ Removed {removed} watchlist entr(y/ies).[/]")

    def _display_privacy_preview(self, iocs: list[IOC], enrichers: list, privacy_mode: str) -> None:
        table = Table(title=f"Privacy Preview ({privacy_mode})", show_lines=True)
        table.add_column("Original IOC", overflow="fold")
        table.add_column("Value sent", overflow="fold")
        table.add_column("Provider")
        table.add_column("Destination", overflow="fold")
        for ioc in iocs:
            safe_ioc = sanitize_ioc_for_external(ioc)
            compatible = [e for e in enrichers if ioc.ioc_type in e.supports]
            if privacy_mode == "local-only" or not compatible:
                destination = "Local cache only" if privacy_mode == "local-only" else "No compatible provider"
                table.add_row(Text(ioc.value), Text("Not sent"), Text("—"), Text(destination))
                continue
            for enricher in compatible:
                hosts = ", ".join(f"https://{host}" for host in sorted(enricher.allowed_hosts))
                table.add_row(Text(ioc.value), Text(safe_ioc.value), Text(enricher.name), Text(hosts))
        console.print(table)

    def _record_watchlist_observations(
        self, results: list[EnrichmentResult], *, persist: bool
    ) -> list[dict]:
        changes = []
        for result in results:
            observation = self.store.record_watchlist_observation(result, persist=persist)
            if observation is not None:
                changes.append(observation)
        return changes

    @staticmethod
    def _display_watchlist_changes(changes: list[dict]) -> None:
        changed = [item for item in changes if item["is_baseline"] or item["changed_fields"]]
        if not changed:
            if changes:
                console.print("[dim]Watchlist checked; no monitored fields changed.[/]")
            return
        table = Table(title="Watchlist Changes", show_lines=True)
        table.add_column("IOC", overflow="fold")
        table.add_column("Change")
        table.add_column("Fields")
        for item in changed:
            state = "Baseline established" if item["is_baseline"] else "Changed"
            fields = ", ".join(item["changed_fields"])
            table.add_row(str(item["ioc"]), state, fields)
        console.print(table)

    def _build_decision_cards(self, results: List[EnrichmentResult]) -> list:
        """Produce a Patch/Isolate/Monitor/Not-affected card for every CVE result."""
        from src.decision.asset_correlation import correlate
        from src.decision.cve_decision import decide
        from src.models import IOCType

        assets = self.store.list_assets()
        cards = []
        for result in results:
            if result.ioc.ioc_type != IOCType.CVE:
                continue
            context = correlate(result, assets)
            cards.append(decide(result, context))

        if cards:
            lines = "\n".join(f"[bold]{c.cve_id}[/]: [cyan]{c.decision.value}[/] — {c.reasons[0]}" for c in cards)
            console.print(Panel(lines, title="[bold blue]CVE Decision Cards[/]", border_style="blue"))
        return cards

    def _export_results(self, results: List[EnrichmentResult]) -> None:
        """Send results to opted-in, configured SIEM destinations."""
        from src.exporters.dispatcher import build_exporters, export_results

        exporters = build_exporters(
            self.config, selected=self.args.export, verify_tls=not getattr(self.args, "export_insecure_tls", False)
        )
        if not exporters:
            console.print(
                "[yellow]⚠ No configured SIEM exporters match --export; "
                "check the relevant settings in config/keys.env.[/]"
            )
            return

        safe_results = [sanitize_result_for_output(result, self.config.secret_values()) for result in results]
        for outcome in export_results(exporters, safe_results):
            if outcome.success:
                console.print(f"[green]✓ Exported {outcome.sent} event(s) to {outcome.exporter}[/]")
            else:
                console.print(f"[red]✗ Export to {outcome.exporter} failed:[/] {outcome.error}")

    def _build_evidence_pack(self, investigation_id: str, results: List[EnrichmentResult], decision_cards: list) -> None:
        from src.evidence.pack import EvidencePackBuilder
        from src.decision.asset_correlation import correlate
        from src.models import IOCType

        assets = []
        if decision_cards:
            card_cves = {card.cve_id for card in decision_cards}
            inventory = self.store.list_assets()
            seen_assets: set[tuple] = set()
            for result in results:
                if result.ioc.ioc_type != IOCType.CVE or result.ioc.value not in card_cves:
                    continue
                for asset in correlate(result, inventory).matched_assets:
                    # Exclude database bookkeeping and inventory file paths
                    # from the portable evidence artifact.
                    evidence_asset = {
                        key: asset.get(key)
                        for key in (
                            "hostname", "ip_address", "criticality",
                            "internet_facing", "owner", "product",
                        )
                    }
                    identity = (
                        asset.get("id"),
                        evidence_asset["hostname"],
                        evidence_asset["ip_address"],
                    )
                    if identity not in seen_assets:
                        seen_assets.add(identity)
                        assets.append(evidence_asset)
        path = EvidencePackBuilder(output_dir=self.args.output).build(
            investigation_id,
            results,
            decision_cards=decision_cards or None,
            matched_assets=assets or None,
            secrets=self.config.secret_values(),
        )
        console.print(f"[green]✓ Evidence pack saved:[/] [bold]{path}[/]")

    def _collect_iocs(self) -> List[IOC]:
        """Gather IOCs from CLI arguments and/or log file."""
        if getattr(self.args, "watchlist_scan", False):
            allow_private = (
                getattr(self.args, "privacy_mode", "standard") == "local-only"
                or getattr(self.args, "allow_private_iocs", False)
            )
            iocs = []
            try:
                entries = self.store.list_watchlist()
                if len(entries) > self.config.max_iocs:
                    console.print(
                        f"[yellow]⚠ Watchlist scan limited to {self.config.max_iocs} IOCs; "
                        f"{len(entries) - self.config.max_iocs} entries were skipped.[/]"
                    )
                for entry in entries[:self.config.max_iocs]:
                    ioc_type = IOCType(entry["ioc_type"])
                    iocs.append(
                        IOC(
                            validate_ioc(entry["ioc_value"], ioc_type, allow_private=allow_private),
                            ioc_type,
                        )
                    )
            except (IOCValidationError, ValueError) as exc:
                self._watchlist_scan_invalid = True
                console.print(
                    f"[red]✗ Watchlist scan stopped:[/] {exc}. "
                    "Use --allow-private-iocs to send private or reserved IOCs to providers."
                )
                return []
            return iocs
        iocs: List[IOC] = []
        parser = IOCParser(self.config.max_file_bytes, self.config.max_iocs)

        # Explicit CLI inputs
        explicit = IOCParser.from_args(
            ips=self.args.ip,
            domains=self.args.domain,
            hashes=self.args.hash,
            cves=self.args.cve,
            allow_private=self.args.allow_private_iocs,
            max_iocs=self.config.max_iocs,
        )
        provided_count = sum(len(values or []) for values in (self.args.ip, self.args.domain, self.args.hash, self.args.cve))
        if provided_count > self.config.max_iocs:
            console.print(f"[yellow]⚠ Explicit IOC inputs limited to {self.config.max_iocs} values.[/]")
        iocs.extend(explicit)

        # Log file
        if self.args.file:
            log_format = getattr(self.args, "log_format", "auto") or "auto"
            if log_format == "auto":
                log_format = self._detect_log_format(self.args.file)

            if log_format == "text":
                console.print("[blue]📂 Parsing log file (text).[/]")
                parse_result = parser.parse_file(self.args.file)
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
                if parse_result.truncated:
                    console.print(f"[yellow]⚠ IOC limit ({self.config.max_iocs}) reached; remaining entries were skipped.[/]")
            else:
                console.print(f"[blue]📂 Parsing log file ({log_format}).[/]")
                log_result = self._parse_structured_log(log_format, self.args.file)
                console.print(
                    "  Extracted → " + "  ".join(f"[cyan]{k}[/]: {v}" for k, v in log_result.stats.items() if v)
                    + (f"  [dim](skipped {log_result.malformed_lines} malformed lines)[/]" if log_result.malformed_lines else "")
                )
                iocs.extend(log_result.iocs)
                if log_result.truncated:
                    console.print("[yellow]⚠ Log parsing limit reached; remaining entries were skipped.[/]")

        # Deduplicate by value+type
        seen: set[str] = set()
        unique: List[IOC] = []
        for ioc in iocs:
            key = f"{ioc.ioc_type}:{ioc.value.lower()}"
            if key not in seen:
                seen.add(key)
                unique.append(ioc)

        if len(unique) > self.config.max_iocs:
            console.print(f"[yellow]⚠ IOC limit ({self.config.max_iocs}) reached; remaining entries were skipped.[/]")
        return unique[:self.config.max_iocs]

    def _detect_log_format(self, path: str) -> str:
        """Best-effort format sniffing for --log-format auto."""
        lower = path.lower()
        if "eve" in lower and lower.endswith(".json"):
            return "suricata"
        if "sysmon" in lower:
            return "sysmon"
        if lower.endswith((".jsonl", ".ndjson")):
            return "jsonl"
        from src.parsers.common import check_file_size

        try:
            check_file_size(path, self.config.max_file_bytes)
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                first_line = handle.readline(4096)
        except OSError:
            return "text"
        stripped = first_line.strip()
        if stripped.startswith("#separator") or stripped.startswith("#fields"):
            return "zeek"
        if stripped.startswith("{"):
            return "jsonl"
        return "text"

    def _parse_structured_log(self, log_format: str, path: str):
        max_bytes = self.config.max_file_bytes
        max_lines = self.config.max_log_lines
        max_iocs = self.config.max_iocs

        if log_format == "zeek":
            from src.parsers.zeek import ZeekParser
            return ZeekParser(max_file_bytes=max_bytes, max_lines=max_lines, max_iocs=max_iocs).parse_file(path)
        if log_format == "suricata":
            from src.parsers.suricata import SuricataParser
            return SuricataParser(max_file_bytes=max_bytes, max_lines=max_lines, max_iocs=max_iocs).parse_file(path)
        if log_format == "sysmon":
            from src.parsers.sysmon import SysmonParser
            return SysmonParser(max_file_bytes=max_bytes, max_lines=max_lines, max_iocs=max_iocs).parse_file(path)
        if log_format == "jsonl":
            from src.parsers.jsonl import JSONLParser
            return JSONLParser(max_file_bytes=max_bytes, max_lines=max_lines, max_iocs=max_iocs).parse_file(path)
        raise ValueError(f"Unsupported log format: {log_format}")

    def _run_enrichment(
        self, iocs: List[IOC], enrichers: list
    ) -> List[EnrichmentResult]:
        results: List[EnrichmentResult] = []

        # EPSS supports batch lookups; prefetch scores for every CVE in this
        # run up front so bulk CVE scans cost a handful of requests instead
        # of one request per CVE.
        for enricher in enrichers:
            if hasattr(enricher, "prefetch"):
                cve_values = [i.value for i in iocs if i.ioc_type == IOCType.CVE]
                if cve_values:
                    enricher.prefetch(cve_values)

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
                provider_scope = "v1:" + ",".join(
                    sorted(e.name for e in enrichers if ioc.ioc_type in e.supports)
                )
                local_only = getattr(self.args, "privacy_mode", "standard") == "local-only"
                bypass_result_cache = self.args.no_cache or getattr(self.args, "watchlist_scan", False)
                if local_only:
                    result = (
                        self.store.get_cached_any_scope(ioc, int(time.time()))
                        if not self.args.no_cache
                        else None
                    )
                elif bypass_result_cache:
                    result = None
                else:
                    result = self.store.get_cached(ioc, int(time.time()), provider_scope)
                if result:
                    result.cached = True
                    result.explanation.append("Returned from the local cache.")
                else:
                    if local_only:
                        result = EnrichmentResult(ioc=ioc)
                        result.errors["privacy"] = "No unexpired local result; external lookups are disabled"
                        result.set_verdict()
                    else:
                        external_ioc = sanitize_ioc_for_external(ioc)
                        result = enrich_ioc(
                            ioc,
                            enrichers,
                            external_ioc=external_ioc,
                            allow_private=self.args.allow_private_iocs,
                        )
                    if not self.args.no_cache and not local_only and not getattr(self.args, "watchlist_scan", False) and self.args.cache_ttl:
                        self.store.cache_result(
                            result,
                            int(time.time()) + self.args.cache_ttl,
                            provider_scope,
                        )
                results.append(result)
                progress.advance(task)

        return results

    def _save_reports(self, results: List[EnrichmentResult]):
        fmt = self.args.format
        out = self.args.output
        saved = []

        try:
            if fmt in ("excel", "all"):
                path = ExcelReporter().generate(results, output_dir=out, secrets=self.config.secret_values())
                saved.append(("Excel", path))

            if fmt in ("json", "all"):
                path = JSONReporter().generate(results, output_dir=out, secrets=self.config.secret_values())
                saved.append(("JSON", path))

            if fmt in ("csv", "all"):
                path = CSVReporter().generate(results, output_dir=out, secrets=self.config.secret_values())
                saved.append(("CSV", path))

            console.print()
            for fmt_name, path in saved:
                console.print(f"[green]✓ {fmt_name} report saved:[/] [bold]{path}[/]")

        except Exception as e:
            self.logger.error("Failed to save report: %s", redact_secrets(e, *self.config.secret_values()))

    @staticmethod
    def _ioc_type_summary(iocs: List[IOC]) -> str:
        from collections import Counter
        counts = Counter(i.ioc_type.value for i in iocs)
        return "  " + "  ".join(f"[cyan]{t}[/]: {c}" for t, c in sorted(counts.items()))
