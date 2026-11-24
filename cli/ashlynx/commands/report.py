from pathlib import Path
from uuid import UUID
import typer
from rich.console import Console

from shared.schemas.report import ReportFormat
from backend.app.reporting.manager import ReportManager
from backend.app.scanner.orchestration.scan_orchestrator import scan_registry
from backend.app.core.exceptions import ScanConfigurationError

console = Console()
report_app = typer.Typer(help="Export and convert security scan reports.")
report_manager = ReportManager()


@report_app.command("export")
def export_report(
    scan_id: str = typer.Argument(..., help="UUID of the scan job"),
    format_type: str = typer.Option("html", "--format", "-f", help="Export format: json, html, markdown, sarif"),
    output_path: Path = typer.Option(Path("./report.html"), "--output", "-o", help="Target output file path"),
):
    """Exports a completed scan to the specified report format."""
    try:
        parsed_uuid = UUID(scan_id)
    except ValueError:
        console.print(f"[bold red][!] Invalid Scan ID:[/bold red] '{scan_id}'. Must be a valid UUID.")
        raise typer.Exit(code=2)

    report = scan_registry.get_report(parsed_uuid)
    if not report:
        console.print(f"[bold red][!] Report Not Found:[/bold red] Scan '{scan_id}' has no completed report in registry.")
        raise typer.Exit(code=1)

    try:
        fmt = ReportFormat(format_type.lower())
    except ValueError:
        valid_formats = [f.value for f in ReportFormat]
        console.print(f"[bold red][!] Invalid report format:[/bold red] '{format_type}'. Supported: {', '.join(valid_formats)}")
        raise typer.Exit(code=2)

    console.print(f"[bold green][*][/bold green] Exporting scan [cyan]{scan_id}[/cyan] to [yellow]{fmt.value}[/yellow]...")

    try:
        dest = report_manager.export_to_file(
            report=report,
            format_type=fmt,
            output_path=output_path,
        )
        console.print(f"[bold green]✓[/bold green] Report successfully exported to: [cyan]{dest}[/cyan]")
    except ScanConfigurationError as sce:
        console.print(f"[bold red][!] Export Failed:[/bold red] {sce}")
        raise typer.Exit(code=1)
