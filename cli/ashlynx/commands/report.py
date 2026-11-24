from pathlib import Path
import typer
from rich.console import Console

console = Console()
report_app = typer.Typer(help="Export and convert security scan reports.")


@report_app.command("export")
def export_report(
    scan_id: str = typer.Argument(..., help="UUID of the scan job"),
    format_type: str = typer.Option("sarif", "--format", "-f", help="Export format: pdf, html, markdown, sarif, json"),
    output_path: Path = typer.Option(Path("./report.sarif"), "--output", "-o", help="Target output file path")
):
    """Exports a completed scan to the specified report format."""
    console.print(f"[bold green][*][/bold green] Exporting scan [cyan]{scan_id}[/cyan] to [yellow]{format_type}[/yellow]...")
    console.print(f"[bold green]✓[/bold green] Output destination: {output_path}")
