from typing import List, Dict, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

console = Console()

SEVERITY_STYLES = {
    "CRITICAL": "bold white on red",
    "HIGH": "bold red",
    "MEDIUM": "bold yellow",
    "LOW": "bold cyan",
    "INFORMATIONAL": "dim white"
}


class TerminalFormatter:
    """Renders formatted, color-coded terminal reports using Rich."""

    @staticmethod
    def print_banner(app_name: str, version: str) -> None:
        title = Text(f"{app_name} [v{version}]", style="bold cyan")
        subtitle = Text("Automated DAST & Vulnerability Assessment Platform", style="italic white")
        console.print(Panel(subtitle, title=title, border_style="cyan"))

    @staticmethod
    def render_findings_table(findings: List[Dict[str, Any]]) -> None:
        if not findings:
            console.print("[bold green]✓ Zero vulnerabilities detected.[/bold green]")
            return

        table = Table(title="Security Findings Summary", border_style="bright_black")
        table.add_column("Severity", style="bold", width=14)
        table.add_column("Vulnerability Title", style="white")
        table.add_column("CWE", style="dim", width=10)
        table.add_column("CVSS", justify="right", width=6)
        table.add_column("Status", width=12)
        table.add_column("Endpoint", style="cyan")

        for f in findings:
            sev = f.get("severity", "MEDIUM")
            style = SEVERITY_STYLES.get(sev, "white")
            table.add_row(
                f"[{style}]{sev}[/{style}]",
                f.get("title", "Unknown"),
                f.get("cwe_id", "CWE-Unknown"),
                str(f.get("cvss_score", "0.0")),
                f.get("status", "SUSPECTED"),
                f.get("endpoint", {}).get("url", "-")
            )

        console.print(table)
