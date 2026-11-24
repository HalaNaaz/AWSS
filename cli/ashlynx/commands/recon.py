import asyncio
import json
import sys
from pathlib import Path
from typing import Optional, List, Tuple
import typer
from rich.console import Console
from rich.table import Table

from cli.ashlynx.output.formatter import TerminalFormatter
from backend.app.scanner.crawler.normalizer import URLNormalizer
from backend.app.scanner.reconnaissance.orchestrator import ReconOrchestrator
from shared.schemas.common import ScopeRuleType

console = Console()


def run_recon(
    target: str = typer.Option(..., "--target", "-t", help="Target URL to assess (e.g. https://example.com)"),
    max_depth: int = typer.Option(3, "--max-depth", "-d", help="Maximum crawl depth"),
    max_pages: int = typer.Option(100, "--max-pages", "-p", help="Maximum number of pages/endpoints to discover"),
    concurrency: int = typer.Option(5, "--concurrency", "-c", help="Concurrent request limit"),
    format_out: str = typer.Option("table", "--format", "-f", help="Output format: table, json"),
    scope_file: Optional[Path] = typer.Option(None, "--scope-file", "-s", help="Path to scope rules file (regex patterns)"),
    authorized: bool = typer.Option(False, "--authorized", "-a", help="Explicit acknowledgment of authorization to assess this target")
):
    """Executes asynchronous attack surface reconnaissance and HTTP crawling on an authorized target."""
    if not authorized:
        console.print("[bold red][!] Target Authorization Required:[/bold red] You must pass [yellow]--authorized[/yellow] to confirm explicit written consent to assess this target.")
        console.print("[dim]Example: ashlynx recon --target https://app.example.com --authorized[/dim]")
        raise typer.Exit(code=2)

    # Validate target URL syntax
    norm_url = URLNormalizer.normalize_url(target)
    if not norm_url:
        console.print(f"[bold red][!] Invalid Target URL:[/bold red] '{target}' is not a valid HTTP/HTTPS address.")
        raise typer.Exit(code=1)

    if format_out != "json":
        TerminalFormatter.print_banner("Ashlynx WebSec Scanner", "2.0.0-dev")
        console.print(f"[bold green][*][/bold green] Initializing Reconnaissance Engine...")
        console.print(f"    Target: [cyan]{norm_url}[/cyan]")
        console.print(f"    Max Depth: {max_depth} | Max Pages: {max_pages} | Concurrency: {concurrency}")

    # Load scope rules if provided
    scope_rules: List[Tuple[ScopeRuleType, str]] = []
    if scope_file and scope_file.exists():
        with open(scope_file, "r") as sf:
            for line in sf:
                line = line.strip()
                if line and not line.startswith("#"):
                    rule_type = ScopeRuleType.EXCLUDE if line.startswith("!") else ScopeRuleType.INCLUDE
                    pattern = line[1:].strip() if line.startswith("!") else line
                    scope_rules.append((rule_type, pattern))

    # Run orchestrator in asyncio loop
    orchestrator = ReconOrchestrator(
        target_url=norm_url,
        scope_rules=scope_rules,
        max_depth=max_depth,
        max_urls=max_pages,
        concurrency=concurrency,
        analyze_javascript=True,
        respect_robots=True
    )

    try:
        summary = asyncio.run(orchestrator.run())
    except Exception as exc:
        console.print(f"[bold red][!] Reconnaissance failed:[/bold red] {str(exc)}")
        raise typer.Exit(code=1)

    # Output formatting
    if format_out == "json":
        print(summary.model_dump_json(indent=2))
        return

    # Render Rich Tables
    console.print(f"\n[bold green]✓[/bold green] [bold white]Reconnaissance Completed[/bold white] in [cyan]{summary.execution_time_seconds}s[/cyan]")
    console.print(f"    Endpoints Discovered: [bold cyan]{summary.endpoints_discovered}[/bold cyan]")
    console.print(f"    Forms Discovered:     [bold yellow]{summary.forms_discovered}[/bold yellow]")
    console.print(f"    Technologies Found:   [bold magenta]{summary.technologies_detected}[/bold magenta]")
    console.print(f"    Passive Findings:     [bold red]{summary.findings_count}[/bold red]\n")

    # Technology Table
    if summary.technologies:
        tech_table = Table(title="Detected Technologies & Frameworks", border_style="bright_black")
        tech_table.add_column("Technology", style="bold white")
        tech_table.add_column("Category", style="cyan")
        tech_table.add_column("Version", style="yellow")
        tech_table.add_column("Confidence", justify="right")
        tech_table.add_column("Source", style="dim")

        for t in summary.technologies:
            tech_table.add_row(
                t.technology_name,
                t.category,
                t.version or "-",
                f"{int(t.confidence * 100)}%",
                t.detection_source
            )
        console.print(tech_table)

    # Category Breakdown
    if summary.categories_breakdown:
        cat_table = Table(title="Endpoint Category Distribution", border_style="bright_black")
        cat_table.add_column("Category", style="white")
        cat_table.add_column("Count", justify="right", style="cyan")
        for cat, count in summary.categories_breakdown.items():
            cat_table.add_row(cat, str(count))
        console.print(cat_table)

    # Passive Findings Table
    if summary.findings:
        find_table = Table(title="Passive Security Analysis Findings", border_style="bright_red")
        find_table.add_column("Severity", style="bold")
        find_table.add_column("Title", style="white")
        find_table.add_column("CWE", style="yellow")
        find_table.add_column("URL", style="dim")
        for f in summary.findings:
            sev_color = "red" if f.severity in ("CRITICAL", "HIGH") else "yellow" if f.severity == "MEDIUM" else "cyan"
            find_table.add_row(
                f"[{sev_color}]{f.severity}[/{sev_color}]",
                f.title,
                f.cwe_id,
                f.endpoint.url if hasattr(f, "endpoint") else "-"
            )
        console.print("\n")
        console.print(find_table)
