import asyncio
import json
from pathlib import Path
from typing import Optional, List
import typer
from rich.console import Console
from rich.table import Table

from cli.ashlynx.output.formatter import TerminalFormatter
from backend.app.scanner.crawler.normalizer import URLNormalizer
from backend.app.scanner.reconnaissance.orchestrator import ReconOrchestrator
from shared.schemas.discovery import PriorityLevel, ParameterCategory, APIType

console = Console()


def run_attack_surface(
    target: str = typer.Argument(..., help="Target URL to assess (e.g. https://example.com)"),
    authorized: bool = typer.Option(False, "--authorized", "-a", help="Explicit confirmation of scanning authorization"),
    max_depth: int = typer.Option(3, "--max-depth", "-d", help="Maximum crawl depth"),
    max_pages: int = typer.Option(100, "--max-pages", "-u", help="Maximum URLs/endpoints to discover"),
    concurrency: int = typer.Option(5, "--concurrency", "-c", help="Concurrency limit"),
    format_out: str = typer.Option("table", "--format", "-f", help="Output format: table, json, graph-json, cytoscape"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Target output file path to write results"),
    show_prioritized: bool = typer.Option(False, "--prioritized", "-p", help="Display prioritized exploration queue"),
    show_parameters: bool = typer.Option(False, "--parameters", help="Display classified parameters breakdown"),
    show_apis: bool = typer.Option(False, "--apis", help="Display discovered API endpoints"),
    show_assets: bool = typer.Option(False, "--assets", help="Display cataloged client assets")
):
    """Executes advanced attack surface discovery, parameter intelligence, API mapping, and graph generation."""
    if not authorized:
        console.print("[bold red][!] Target Authorization Required:[/bold red] You must pass [yellow]--authorized[/yellow] / [yellow]-a[/yellow] to confirm explicit written consent to assess this target.")
        console.print("[dim]Example: ashlynx attack-surface https://app.example.com --authorized[/dim]")
        raise typer.Exit(code=2)

    norm_url = URLNormalizer.normalize_url(target)
    if not norm_url:
        console.print(f"[bold red][!] Invalid Target URL:[/bold red] '{target}'. Must start with http:// or https://")
        raise typer.Exit(code=1)

    if format_out not in ("json", "graph-json", "cytoscape"):
        TerminalFormatter.print_banner("Ashlynx WebSec Scanner", "2.0.0-dev")
        console.print(f"[bold green][*][/bold green] Initializing Attack Surface Intelligence Engine...")
        console.print(f"    Target: [cyan]{norm_url}[/cyan]")
        console.print(f"    Max Depth: {max_depth} | Max Pages: {max_pages} | Concurrency: {concurrency}")

    orchestrator = ReconOrchestrator(
        target_url=norm_url,
        max_depth=max_depth,
        max_urls=max_pages,
        concurrency=concurrency,
        analyze_javascript=True,
        respect_robots=True
    )

    try:
        with console.status(f"[bold cyan]Mapping attack surface for {norm_url}...[/bold cyan]", spinner="dots"):
            summary = asyncio.run(orchestrator.run())
    except Exception as exc:
        console.print(f"[bold red][!] Attack surface discovery failed:[/bold red] {str(exc)}")
        raise typer.Exit(code=1)

    engine = orchestrator.discovery_engine
    surface_summary = engine.get_summary()
    prioritized_endpoints = engine.get_prioritized_endpoints()
    parameters = engine.parameter_engine.get_parameters()
    apis = engine.api_engine.get_api_endpoints()
    assets = engine.asset_engine.get_assets()

    # Graph Export
    if format_out == "graph-json":
        graph_data = engine.graph.to_schema().model_dump(mode="json")
        out_str = json.dumps(graph_data, indent=2)
        if output:
            output.write_text(out_str, encoding="utf-8")
            console.print(f"[bold green]✓[/bold green] Attack Surface Graph exported to: [cyan]{output}[/cyan]")
        else:
            print(out_str)
        return

    if format_out == "cytoscape":
        cyto_data = engine.graph.to_cytoscape()
        out_str = json.dumps(cyto_data, indent=2)
        if output:
            output.write_text(out_str, encoding="utf-8")
            console.print(f"[bold green]✓[/bold green] Cytoscape Graph exported to: [cyan]{output}[/cyan]")
        else:
            print(out_str)
        return

    if format_out == "json":
        full_result = {
            "summary": surface_summary.model_dump(mode="json"),
            "prioritized_endpoints": [p.model_dump(mode="json") for p in prioritized_endpoints],
            "parameters": [p.model_dump(mode="json") for p in parameters],
            "apis": [a.model_dump(mode="json") for a in apis],
            "assets": [a.model_dump(mode="json") for a in assets],
            "graph": engine.graph.to_schema().model_dump(mode="json")
        }
        out_str = json.dumps(full_result, indent=2)
        if output:
            output.write_text(out_str, encoding="utf-8")
            console.print(f"[bold green]✓[/bold green] Attack surface results exported to: [cyan]{output}[/cyan]")
        else:
            print(out_str)
        return

    # Render Table Summary
    console.print(f"\n[bold green]✓[/bold green] [bold white]Attack Surface Discovery Completed[/bold white]")
    console.print(f"    Total Endpoints Discovered:   [bold cyan]{surface_summary.total_endpoints}[/bold cyan]")
    console.print(f"    Classified Parameters:        [bold yellow]{surface_summary.total_parameters}[/bold yellow]")
    console.print(f"    API Routes Cataloged:         [bold magenta]{surface_summary.total_apis}[/bold magenta]")
    console.print(f"    Client Assets Mapped:         [bold blue]{surface_summary.total_assets}[/bold blue]")
    console.print(f"    Technologies Detected:        [bold green]{surface_summary.total_technologies}[/bold green]")
    console.print(f"    Graph Topology:               [bold white]{surface_summary.graph_nodes_count} nodes / {surface_summary.graph_edges_count} edges[/bold white]")
    console.print(f"    High-Priority Targets:        [bold red]{surface_summary.high_priority_endpoints_count}[/bold red]\n")

    # Prioritization Queue Table
    if show_prioritized or not (show_parameters or show_apis or show_assets):
        pri_table = Table(title="Top Prioritized Endpoints (Exploration Queue)", border_style="bright_black")
        pri_table.add_column("Priority", style="bold")
        pri_table.add_column("Score", justify="right")
        pri_table.add_column("Method", style="cyan")
        pri_table.add_column("URL", style="white")
        pri_table.add_column("Key Signals", style="dim")

        for p in prioritized_endpoints[:15]:
            pri_color = "red" if p.priority_level == PriorityLevel.HIGH else ("yellow" if p.priority_level == PriorityLevel.MEDIUM else "blue")
            signals_text = "; ".join(p.risk_signals[:2]) if p.risk_signals else "-"
            pri_table.add_row(
                f"[{pri_color}]{p.priority_level.value}[/{pri_color}]",
                str(p.priority_score),
                p.method,
                p.url,
                signals_text
            )
        console.print(pri_table)

    # Parameters Table
    if show_parameters and parameters:
        p_table = Table(title="Parameter Intelligence & Heuristic Classification", border_style="bright_black")
        p_table.add_column("Parameter", style="bold white")
        p_table.add_column("Location", style="cyan")
        p_table.add_column("Category", style="yellow")
        p_table.add_column("Confidence", justify="right")
        p_table.add_column("Sample (Redacted)", style="dim")
        p_table.add_column("Risk Signal", style="red")

        for param in parameters[:25]:
            sample = param.sample_values_redacted[0] if param.sample_values_redacted else "-"
            sig = param.risk_signals[0] if param.risk_signals else "-"
            p_table.add_row(
                param.name,
                param.location.value,
                param.category.value,
                f"{int(param.confidence * 100)}%",
                sample,
                sig
            )
        console.print(p_table)

    # API Inventory Table
    if show_apis and apis:
        api_table = Table(title="Discovered API Routes & Architectures", border_style="bright_black")
        api_table.add_column("Type", style="magenta")
        api_table.add_column("Method", style="cyan")
        api_table.add_column("URL", style="white")
        api_table.add_column("Version", style="yellow")
        api_table.add_column("Auth Required", justify="center")

        for a in apis[:25]:
            auth_str = "[red]YES[/red]" if a.auth_required else "[green]NO[/green]"
            api_table.add_row(
                a.api_type.value,
                a.method,
                a.url,
                a.version or "-",
                auth_str
            )
        console.print(api_table)

    # Asset Table
    if show_assets and assets:
        ass_table = Table(title="Mapped Client Assets", border_style="bright_black")
        ass_table.add_column("Type", style="cyan")
        ass_table.add_column("URL", style="white")
        ass_table.add_column("MIME", style="dim")
        ass_table.add_column("Source", style="yellow")

        for ass in assets[:25]:
            ass_table.add_row(
                ass.asset_type.value,
                ass.url,
                ass.mime_type or "-",
                ass.discovery_source
            )
        console.print(ass_table)
