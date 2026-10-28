"""Terminal presentation helpers for the local investigation history."""

from __future__ import annotations

from typing import Any

from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text

console = Console()


def display_history(rows: list[dict[str, Any]], *, title: str = "Local Investigation History") -> None:
    """Render bounded investigation observations without interpreting values as markup."""
    if not rows:
        console.print("[yellow]No matching local investigation history was found.[/]")
        return

    table = Table(title=title, box=box.ROUNDED, show_lines=True)
    table.add_column("Observed (UTC)", style="dim", no_wrap=True)
    table.add_column("IOC", overflow="fold")
    table.add_column("Type", no_wrap=True)
    table.add_column("Verdict", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Confidence", justify="right", no_wrap=True)
    table.add_column("Sources", overflow="fold")
    table.add_column("Investigation ID", style="dim", overflow="fold")

    for row in rows:
        table.add_row(
            Text(str(row.get("created_at", ""))),
            Text(str(row.get("ioc_value", ""))),
            Text(str(row.get("ioc_type", ""))),
            Text(str(row.get("verdict", "Unknown"))),
            Text(str(row.get("severity") or "—")),
            Text(str(row.get("confidence_score", 0))),
            Text(", ".join(str(item) for item in row.get("sources", [])) or "—"),
            Text(str(row.get("investigation_id", ""))),
        )
    console.print(table)


def display_related_iocs(rows: list[dict[str, Any]], *, title: str = "Co-occurring IOCs") -> None:
    """Show indicators previously stored in the same investigation, without implying causality."""
    if not rows:
        console.print("[dim]No co-occurring IOCs were found in saved investigations.[/]")
        return

    table = Table(title=title, box=box.SIMPLE)
    table.add_column("IOC")
    table.add_column("Type")
    table.add_column("Shared investigations", justify="right")
    table.add_column("Last seen (UTC)")
    for row in rows:
        table.add_row(
            Text(str(row.get("ioc_value", ""))),
            Text(str(row.get("ioc_type", ""))),
            str(row.get("shared_investigations", 0)),
            Text(str(row.get("last_seen", ""))),
        )
    console.print(table)
