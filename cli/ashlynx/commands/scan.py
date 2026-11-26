import asyncio
from typing import Optional
from pathlib import Path
from uuid import uuid4
import typer
from rich.console import Console

from cli.ashlynx.output.formatter import TerminalFormatter
from shared.schemas.common import ScanProfile
from shared.schemas.report import ReportFormat
from backend.app.scanner.orchestration.scan_orchestrator import (
    ScanOrchestrator,
    scan_registry,
)
from backend.app.reporting.manager import ReportManager
from backend.app.core.config import settings
from backend.app.core.exceptions import ScanConfigurationError

console = Console()
report_manager = ReportManager()


def run_scan(
    target: str = typer.Argument(..., help="Target URL to assess (e.g., https://example.com)"),
    profile: str = typer.Option("SAFE_ACTIVE", "--profile", "-p", help="Scan profile: safe-active, standard-active, passive-only, quick-assessment, full-assessment"),
    authorized: bool = typer.Option(False, "--authorized", "-a", help="Explicit confirmation of scanning authorization (Safety Gate)"),
    modules: Optional[str] = typer.Option(None, "--modules", "-m", help="Comma-separated list of active modules/analyzers to enable"),
    request_budget: Optional[int] = typer.Option(None, "--request-budget", "-b", help="Maximum active request budget (default derived from profile)"),
    scope_file: Optional[Path] = typer.Option(None, "--scope-file", "-s", help="Path to in-scope pattern rules file"),
    format_out: str = typer.Option("table", "--format", "-f", help="Output format: table, json, html, markdown, sarif"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Target output file path for report export"),
    max_depth: Optional[int] = typer.Option(None, "--max-depth", "-d", help="Maximum crawl depth override"),
    max_urls: Optional[int] = typer.Option(None, "--max-urls", "-u", help="Maximum URLs to crawl override"),
    concurrency: Optional[int] = typer.Option(None, "--concurrency", "-c", help="Concurrency limit override"),
    rate_limit: Optional[float] = typer.Option(None, "--rate-limit", "-r", help="Requests per second rate limit override"),
    asset_criticality: Optional[float] = typer.Option(None, "--asset-criticality", help="Target asset business criticality (0.5-5.0) for contextual risk scoring"),
    hide_duplicates: bool = typer.Option(False, "--hide-duplicates", help="Hide correlated duplicate findings in table view"),
    fail_on_findings: bool = typer.Option(False, "--fail-on-findings", help="Exit code 1 if critical or high findings are detected (CI gate)"),
):
    """Executes a target assessment through Ashlynx scanner."""
    TerminalFormatter.print_banner("Ashlynx WebSec Scanner", "2.0.0-dev")

    # Safety Gate verification
    if not authorized:
        console.print("[bold red][!] SAFETY GATE VIOLATION:[/bold red] Scanning unauthorized systems is strictly prohibited.")
        console.print("[yellow]You must explicitly pass the '--authorized' / '-a' flag confirming you have authorization to test this target.[/yellow]")
        raise typer.Exit(code=2)

    # Validate target URL format
    if not target.startswith(("http://", "https://")):
        console.print(f"[bold red][!] Invalid target URL:[/bold red] '{target}'. Must start with http:// or https://")
        raise typer.Exit(code=2)

    # Validate and normalize profile
    normalized_profile = profile.replace("-", "_").upper()
    try:
        profile_enum = ScanProfile(normalized_profile)
    except ValueError:
        valid_profiles = [p.value.lower().replace("_", "-") for p in ScanProfile]
        console.print(f"[bold red][!] Invalid scan profile:[/bold red] '{profile}'. Allowed profiles: {', '.join(valid_profiles)}")
        raise typer.Exit(code=2)

    enabled_modules_set = set(m.strip() for m in modules.split(",")) if modules else None

    scan_id = uuid4()
    orchestrator = ScanOrchestrator(
        target_url=target,
        scan_id=scan_id,
        profile=profile_enum,
        max_crawl_depth=max_depth,
        max_urls=max_urls,
        concurrency=concurrency,
        rate_limit_rps=rate_limit,
        request_budget=request_budget,
        enabled_modules=enabled_modules_set,
        asset_criticality=asset_criticality,
    )
    scan_registry.register_orchestrator(orchestrator)

    console.print(f"[bold green][*][/bold green] Initialized Scan [cyan]{scan_id}[/cyan]")
    console.print(f"[bold green][*][/bold green] Target: [cyan]{target}[/cyan]")
    console.print(f"[bold green][*][/bold green] Profile: [yellow]{profile_enum.value}[/yellow]")
    if orchestrator.request_budget > 0:
        console.print(f"[bold yellow][*][/bold yellow] Active Detection Engine: [green]ENABLED[/green] (Budget: {orchestrator.request_budget} probes)")
    else:
        console.print("[dim][*] Active Detection Engine: DISABLED (Passive Inspection Mode)[/dim]")
    console.print(f"[bold green][*][/bold green] Depth: {orchestrator.max_crawl_depth} | Max URLs: {orchestrator.max_urls} | Concurrency: {orchestrator.concurrency} | Rate Limit: {orchestrator.rate_limit_rps} RPS")
    ssrf_mode = (
        "[bold yellow]CONTROLLED LAB (ALLOW_PRIVATE_IPS=true)[/bold yellow]"
        if settings.ALLOW_PRIVATE_IPS
        else "[bold green]STRICT (RFC1918 & Metadata Blocked)[/bold green]"
    )
    console.print(f"[bold green][*][/bold green] ScopeGate Anti-SSRF Pinning: {ssrf_mode} | Authorization: [green]VERIFIED[/green]")
    console.print("[dim]Pre-flight scope validation & anti-SSRF verification initialized...[/dim]")

    # Run assessment with cooperative cancellation handling
    try:
        with console.status(f"[bold cyan]Scanning target {target} [Profile: {profile_enum.value}]...[/bold cyan]", spinner="dots"):
            report = asyncio.run(orchestrator.run())
    except KeyboardInterrupt:
        orchestrator.cancel()
        console.print("\n[bold yellow][!] Scan cancelled by user interrupt.[/bold yellow]")
        raise typer.Exit(code=130)

    # Store finished report in registry
    scan_registry.store_report(report)

    # Handle output format
    fmt_lower = format_out.lower()
    if fmt_lower == "table":
        # Print Rich visual tables
        TerminalFormatter.render_scan_summary_panel(
            target=report.target_url,
            profile=report.profile.value,
            status=report.status.value,
            duration=report.duration_seconds,
            urls=report.urls_crawled,
            findings_count=len(report.findings),
        )
        TerminalFormatter.render_severity_summary(report.severity_summary)
        if report.intelligence_summary:
            TerminalFormatter.render_intelligence_summary(report.intelligence_summary)
        if report.security_coverage:
            TerminalFormatter.render_coverage_summary(report.security_coverage)
        if report.technologies:
            TerminalFormatter.render_technology_table(report.technologies)
        display_findings = [
            f for f in report.findings
            if not (hide_duplicates and f.intelligence and f.intelligence.is_duplicate)
        ]
        TerminalFormatter.render_findings_table(display_findings)
    elif fmt_lower in ("json", "html", "markdown", "sarif"):
        # Map to ReportFormat
        format_map = {
            "json": ReportFormat.JSON,
            "html": ReportFormat.HTML,
            "markdown": ReportFormat.MARKDOWN,
            "sarif": ReportFormat.SARIF,
        }
        target_fmt = format_map[fmt_lower]
        try:
            rendered_content = report_manager.generate_report(report, target_fmt)
            if not output:
                console.print(rendered_content)
        except ScanConfigurationError as sce:
            console.print(f"[bold red][!] Reporting Error:[/bold red] {sce}")
            raise typer.Exit(code=1)
    else:
        console.print(f"[bold red][!] Unknown format:[/bold red] '{format_out}'. Supported: table, json, html, markdown, sarif")
        raise typer.Exit(code=2)

    # Handle report export to file if requested
    if output:
        # Determine format from file extension if format was table
        export_fmt = ReportFormat.JSON
        ext = output.suffix.lower()
        if ext == ".html":
            export_fmt = ReportFormat.HTML
        elif ext in (".md", ".markdown"):
            export_fmt = ReportFormat.MARKDOWN
        elif ext == ".sarif":
            export_fmt = ReportFormat.SARIF
        elif fmt_lower in ("json", "html", "markdown", "sarif"):
            export_fmt = format_map[fmt_lower]

        try:
            saved_path = report_manager.export_to_file(
                report=report,
                format_type=export_fmt,
                output_path=output,
            )
            console.print(f"\n[bold green]✓[/bold green] Report successfully saved to: [cyan]{saved_path}[/cyan]")
        except ScanConfigurationError as sce:
            console.print(f"[bold red][!] Export Error:[/bold red] {sce}")
            raise typer.Exit(code=1)

    # CI Quality Gate Check
    if fail_on_findings:
        crit = report.severity_summary.critical
        high = report.severity_summary.high
        if crit > 0 or high > 0:
            console.print(f"\n[bold red][!] CI Gate Failed:[/bold red] Scan identified {crit} Critical and {high} High severity findings.")
            raise typer.Exit(code=1)
