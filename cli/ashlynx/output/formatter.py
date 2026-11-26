from typing import List, Dict, Any, Union
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from shared.schemas.report import SeveritySummarySchema
from shared.schemas.discovery import TechnologyObservationSchema
from shared.schemas.finding import FindingResponse
from shared.schemas.intelligence import ScanIntelligenceSummarySchema
from shared.schemas.phase6 import SecurityCoverageReportSchema

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
    def render_scan_summary_panel(
        target: str,
        profile: str,
        status: str,
        duration: float,
        urls: int,
        findings_count: int,
    ) -> None:
        status_color = "green" if status == "COMPLETED" else ("yellow" if status == "CANCELLED" else "red")
        text = Text()
        text.append("Target URL:      ", style="bold")
        text.append(f"{target}\n", style="cyan")
        text.append("Profile:         ", style="bold")
        text.append(f"{profile}\n", style="yellow")
        text.append("Lifecycle State: ", style="bold")
        text.append(f"{status}\n", style=f"bold {status_color}")
        text.append("Duration:        ", style="bold")
        text.append(f"{duration:.2f} seconds\n")
        text.append("URLs Crawled:    ", style="bold")
        text.append(f"{urls}\n")
        text.append("Total Findings:  ", style="bold")
        text.append(f"{findings_count}\n", style="bold white")

        console.print(Panel(text, title="[bold cyan]Scan Execution Summary[/bold cyan]", border_style="cyan"))

    @staticmethod
    def render_severity_summary(summary: SeveritySummarySchema) -> None:
        table = Table(title="Executive Vulnerability Breakdown", border_style="bright_black")
        table.add_column("Severity Level", style="bold", width=18)
        table.add_column("Count", justify="right", width=10)

        table.add_row("[bold white on red]CRITICAL[/bold white on red]", str(summary.critical))
        table.add_row("[bold red]HIGH[/bold red]", str(summary.high))
        table.add_row("[bold yellow]MEDIUM[/bold yellow]", str(summary.medium))
        table.add_row("[bold cyan]LOW[/bold cyan]", str(summary.low))
        table.add_row("[dim white]INFORMATIONAL[/dim white]", str(summary.informational))
        table.add_row("[bold white]TOTAL FINDINGS[/bold white]", f"[bold white]{summary.total}[/bold white]")

        console.print(table)

    @staticmethod
    def render_technology_table(technologies: List[TechnologyObservationSchema]) -> None:
        if not technologies:
            return

        table = Table(title="Detected Technologies & Frameworks", border_style="bright_black")
        table.add_column("Technology", style="bold cyan")
        table.add_column("Category", style="yellow")
        table.add_column("Version", style="white")
        table.add_column("Confidence", style="dim")

        for tech in technologies:
            table.add_row(
                tech.technology_name,
                tech.category,
                tech.version or "Unknown",
                f"{tech.confidence:.2f}"
            )

        console.print(table)

    @staticmethod
    def render_findings_table(findings: Union[List[Dict[str, Any]], List[FindingResponse]]) -> None:
        if not findings:
            console.print("[bold green]✓ Zero security weaknesses detected.[/bold green]")
            return

        table = Table(title="Detailed Security Findings", border_style="bright_black")
        table.add_column("Severity", style="bold", width=13)
        table.add_column("Priority", style="bold", width=10)
        table.add_column("Vulnerability Title", style="white")
        table.add_column("CWE", style="dim", width=9)
        table.add_column("Confidence", justify="right", width=12)
        table.add_column("Validation", width=16)
        table.add_column("Correlation", width=16)
        table.add_column("Endpoint", style="cyan")

        for item in findings:
            if isinstance(item, FindingResponse):
                sev = item.severity.value
                title = item.title
                cwe = item.cwe_id or "CWE-Unknown"
                if item.intelligence:
                    conf = f"{item.intelligence.confidence_assessment.level.value} ({int(item.confidence * 100)}%)"
                    stat = item.intelligence.validation_state.value
                    priority = item.intelligence.contextual_risk.contextual_priority.value
                    if item.intelligence.correlation_group_id:
                        role = "DUP" if item.intelligence.is_duplicate else "PRI"
                        corr = f"{role}:{item.intelligence.correlation_group_id[:10]}"
                    else:
                        corr = "INDEP"
                else:
                    conf = f"{item.confidence:.2f}"
                    stat = item.status.value
                    priority = sev
                    corr = "-"
                endpoint = item.endpoint.url if item.endpoint else "-"
            else:
                sev = item.get("severity", "MEDIUM")
                title = item.get("title", "Unknown")
                cwe = item.get("cwe_id", "CWE-Unknown")
                conf_val = item.get("confidence", 0.7)
                conf = f"{conf_val:.2f}" if isinstance(conf_val, (int, float)) else str(conf_val)
                stat = item.get("status", "SUSPECTED")
                priority = sev
                corr = "-"
                endpoint = item.get("endpoint", {}).get("url", "-") if isinstance(item.get("endpoint"), dict) else "-"

            style = SEVERITY_STYLES.get(sev, "white")
            table.add_row(
                f"[{style}]{sev}[/{style}]",
                priority,
                title,
                cwe,
                conf,
                stat,
                corr,
                endpoint
            )

        console.print(table)

    @staticmethod
    def render_intelligence_summary(intel: ScanIntelligenceSummarySchema) -> None:
        table = Table(title="AVIVE Vulnerability Intelligence Summary", border_style="cyan")
        table.add_column("Metric", style="bold white")
        table.add_column("Value", justify="right", style="cyan")

        table.add_row("Total Normalized Findings", str(intel.total_raw_findings))
        table.add_row("Unique Primary Findings", str(intel.unique_primary_findings))
        table.add_row("Duplicate Findings Linked", str(intel.duplicate_findings_count))
        table.add_row("Correlation Groups", str(intel.correlation_groups_count))
        table.add_row("Manual Review Required", str(intel.manual_review_required_count))
        table.add_row("Confidence Breakdown", str(intel.confidence_breakdown))
        table.add_row("Validation Breakdown", str(intel.validation_state_breakdown))
        table.add_row("Contextual Priority Breakdown", str(intel.contextual_priority_breakdown))
        console.print(table)

    @staticmethod
    def render_coverage_summary(cov: SecurityCoverageReportSchema) -> None:
        table = Table(title=f"OWASP Top 10:2021 Security Coverage ({cov.overall_dast_coverage_percent}%)", border_style="blue")
        table.add_column("OWASP Category", style="white")
        table.add_column("Status", style="bold", width=14)
        table.add_column("Findings", justify="right", width=9)
        table.add_column("Explanation", style="dim")

        for entry in cov.owasp_categories:
            st = entry.status.value
            color = "green" if st == "TESTED" else ("yellow" if st == "PARTIAL" else ("cyan" if st == "SKIPPED" else "red"))
            table.add_row(
                f"{entry.owasp_id} {entry.owasp_name}",
                f"[{color}]{st}[/{color}]",
                str(entry.findings_detected),
                entry.explanation,
            )
        console.print(table)
