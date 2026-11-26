import json
from typing import Optional
from uuid import UUID
import httpx
import typer
from rich.console import Console
from rich.table import Table

from backend.app.scanner.intelligence.analytics import SecurityAnalyticsEngine
from backend.app.scanner.orchestration.scan_orchestrator import scan_registry
from shared.schemas.phase6 import ScanAnalyticsSchema, ScanComparisonSchema

analytics_app = typer.Typer(help="Security assessment analytics, OWASP coverage trends, and scan comparison.")
console = Console()


@analytics_app.command("overview", help="Display real-data security analytics across executed scans.")
def analytics_overview_cmd(
    api_url: Optional[str] = typer.Option(None, "--api-url", help="Optional running API URL (e.g. http://127.0.0.1:8000/api/v1)"),
    format_out: str = typer.Option("table", "--format", "-f", help="Output format: table or json"),
):
    if api_url:
        try:
            resp = httpx.get(f"{api_url.rstrip('/')}/analytics/overview", timeout=10.0)
            resp.raise_for_status()
            data = ScanAnalyticsSchema.model_validate(resp.json()["data"])
        except Exception as exc:
            console.print(f"[bold red][!] Failed to fetch analytics:[/bold red] {exc}")
            raise typer.Exit(code=1)
    else:
        data = SecurityAnalyticsEngine.compute_analytics(scan_registry.list_reports())

    if format_out.lower() == "json":
        typer.echo(data.model_dump_json(indent=2))
        return

    table = Table(title="Ashlynx Security Assessment Analytics", border_style="cyan")
    table.add_column("Metric", style="bold white")
    table.add_column("Value", justify="right", style="cyan")
    table.add_row("Total Scans Analyzed", str(data.total_scans_analyzed))
    table.add_row("Total Findings Across Scans", str(data.total_findings_across_scans))
    table.add_row("Average DAST Coverage %", f"{data.average_dast_coverage_percent}%")
    table.add_row("Severity Distribution", str(data.severity_distribution))
    table.add_row("Top Vulnerable Categories", str(data.top_vulnerable_categories))
    console.print(table)


@analytics_app.command("compare", help="Compare two scans by deterministic finding fingerprints.")
def analytics_compare_cmd(
    baseline_id: UUID = typer.Argument(..., help="Baseline scan UUID"),
    current_id: UUID = typer.Argument(..., help="Current scan UUID"),
    api_url: Optional[str] = typer.Option(None, "--api-url"),
    format_out: str = typer.Option("table", "--format", "-f"),
):
    if api_url:
        try:
            resp = httpx.get(
                f"{api_url.rstrip('/')}/analytics/compare",
                params={"baseline_scan_id": str(baseline_id), "current_scan_id": str(current_id)},
                timeout=10.0,
            )
            resp.raise_for_status()
            comp = ScanComparisonSchema.model_validate(resp.json()["data"])
        except Exception as exc:
            console.print(f"[bold red][!] Scan comparison failed:[/bold red] {exc}")
            raise typer.Exit(code=1)
    else:
        b_rep = scan_registry.get_report(baseline_id)
        c_rep = scan_registry.get_report(current_id)
        if not b_rep or not c_rep:
            console.print("[bold red][!] Both baseline and current scan reports must exist in registry.[/bold red]")
            raise typer.Exit(code=1)
        comp = SecurityAnalyticsEngine.compare_scans(b_rep, c_rep)

    if format_out.lower() == "json":
        typer.echo(comp.model_dump_json(indent=2))
        return

    console.print(f"[bold cyan]{comp.summary}[/bold cyan]")
