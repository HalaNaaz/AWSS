import json
from pathlib import Path
from typing import List, Optional
from uuid import UUID
import httpx
import typer
from rich.console import Console
from rich.panel import Panel

from backend.app.api.v1.endpoints.findings import filter_findings_collection
from backend.app.reporting.manager import ReportManager
from backend.app.scanner.intelligence.engine import VulnerabilityIntelligenceEngine
from backend.app.scanner.intelligence.validation import SafeValidationWorkflow
from backend.app.scanner.orchestration.scan_orchestrator import scan_registry
from cli.ashlynx.output.formatter import TerminalFormatter
from shared.schemas.common import Severity
from shared.schemas.finding import FindingResponse
from shared.schemas.intelligence import (
    ConfidenceLevel,
    ContextualPriority,
    ValidationState,
)
from shared.schemas.report import UnifiedScanReport

findings_app = typer.Typer(help="Inspect, filter, correlate, validate, and export enriched AVIVE findings.")
console = Console()


def _load_findings_source(
    scan_id: Optional[UUID],
    input_file: Optional[Path],
    api_url: Optional[str],
) -> List[FindingResponse]:
    if input_file:
        if not input_file.exists():
            console.print(f"[bold red][!] File not found:[/bold red] {input_file}")
            raise typer.Exit(code=1)
        data = json.loads(input_file.read_text(encoding="utf-8"))
        if isinstance(data, dict) and "findings" in data:
            parsed_report = UnifiedScanReport.model_validate(data)
            # Enrich on the fly if legacy Phase 1-4 JSON lacks Phase 5 intelligence
            if parsed_report.findings and not any(f.intelligence for f in parsed_report.findings):
                enriched, _ = VulnerabilityIntelligenceEngine.process_findings(
                    raw_findings=parsed_report.findings,
                    scan_id=parsed_report.scan_id,
                    technologies=parsed_report.technologies,
                )
                return enriched
            return parsed_report.findings
        raise typer.Exit(code=1)

    if api_url:
        params = {}
        if scan_id:
            params["scan_id"] = str(scan_id)
        params["page_size"] = 100
        try:
            resp = httpx.get(f"{api_url.rstrip('/')}/findings/", params=params, timeout=10.0)
            resp.raise_for_status()
            payload = resp.json()
            return [FindingResponse.model_validate(item) for item in payload.get("items", [])]
        except Exception as exc:
            console.print(f"[bold red][!] Failed to fetch findings from API:[/bold red] {exc}")
            raise typer.Exit(code=1)

    if scan_id:
        return scan_registry.get_findings(scan_id)
    return scan_registry.get_all_findings()


@findings_app.command("list", help="List and filter AVIVE-enriched vulnerability findings.")
def list_findings_cmd(
    scan_id: Optional[UUID] = typer.Option(None, "--scan-id", help="Filter by scan job UUID"),
    input_file: Optional[Path] = typer.Option(None, "--input", "-i", help="Load findings from exported JSON scan report"),
    api_url: Optional[str] = typer.Option(None, "--api-url", help="Query running Ashlynx API (e.g. http://127.0.0.1:8000/api/v1)"),
    severity: Optional[str] = typer.Option(None, "--severity", "-s", help="Filter by severity (CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL)"),
    confidence: Optional[str] = typer.Option(None, "--confidence", "-c", help="Filter by confidence level (LOW, MEDIUM, HIGH)"),
    validation: Optional[str] = typer.Option(None, "--validation", "-v", help="Filter by validation state (DETECTED, NEEDS_REVIEW, VALIDATED, ...)"),
    priority: Optional[str] = typer.Option(None, "--priority", "-p", help="Filter by contextual priority (CRITICAL, HIGH, MEDIUM, LOW, INFO)"),
    correlation_group: Optional[str] = typer.Option(None, "--correlation-group", "-g", help="Filter by correlation group ID"),
    hide_duplicates: bool = typer.Option(False, "--hide-duplicates", help="Exclude duplicate findings"),
    format_out: str = typer.Option("table", "--format", "-f", help="Output format: table or json"),
):
    findings = _load_findings_source(scan_id, input_file, api_url)
    sev_enum = Severity(severity.upper()) if severity else None
    conf_enum = ConfidenceLevel(confidence.upper()) if confidence else None
    val_enum = ValidationState(validation.upper()) if validation else None
    prio_enum = ContextualPriority(priority.upper()) if priority else None

    filtered = filter_findings_collection(
        findings=findings,
        scan_id=scan_id,
        severity=sev_enum,
        confidence_level=conf_enum,
        validation_state=val_enum,
        contextual_priority=prio_enum,
        correlation_group_id=correlation_group,
        include_duplicates=not hide_duplicates,
    )

    if format_out.lower() == "json":
        typer.echo(json.dumps([f.model_dump(mode="json") for f in filtered], indent=2))
        return

    TerminalFormatter.render_findings_table(filtered)


@findings_app.command("export", help="Export filtered, AVIVE-enriched findings to a safe JSON file.")
def export_findings_cmd(
    output: Path = typer.Option(..., "--output", "-o", help="Output JSON file path"),
    scan_id: Optional[UUID] = typer.Option(None, "--scan-id"),
    input_file: Optional[Path] = typer.Option(None, "--input", "-i"),
    api_url: Optional[str] = typer.Option(None, "--api-url"),
    hide_duplicates: bool = typer.Option(False, "--hide-duplicates"),
):
    resolved = ReportManager.validate_and_resolve_output_path(output)
    findings = _load_findings_source(scan_id, input_file, api_url)
    filtered = filter_findings_collection(findings=findings, scan_id=scan_id, include_duplicates=not hide_duplicates)

    resolved.parent.mkdir(parents=True, exist_ok=True)
    resolved.write_text(json.dumps([f.model_dump(mode="json") for f in filtered], indent=2), encoding="utf-8")
    console.print(f"[bold green][✓][/bold green] Exported {len(filtered)} enriched findings to [cyan]{resolved}[/cyan]")


@findings_app.command("validate", help="Update validation state for a finding in registry or API.")
def validate_finding_cmd(
    finding_id: UUID = typer.Argument(..., help="Target finding UUID"),
    state: str = typer.Option(..., "--state", "-s", help="Target validation state (NEEDS_REVIEW, VALIDATED, FALSE_POSITIVE, ACCEPTED_RISK, RESOLVED, INCONCLUSIVE)"),
    actor: str = typer.Option("cli_analyst", "--actor", help="Analyst identifier"),
    notes: Optional[str] = typer.Option(None, "--notes", help="Rationale or review notes"),
    api_url: Optional[str] = typer.Option(None, "--api-url", help="Optional running API URL"),
):
    target_state = ValidationState(state.upper())
    if api_url:
        try:
            resp = httpx.post(
                f"{api_url.rstrip('/')}/findings/{finding_id}/validate",
                json={"target_state": target_state.value, "actor": actor, "notes": notes},
                timeout=10.0,
            )
            resp.raise_for_status()
            console.print(Panel(f"Finding [cyan]{finding_id}[/cyan] transitioned to [green]{target_state.value}[/green]", title="Validation Updated"))
            return
        except Exception as exc:
            console.print(f"[bold red][!] API validation failed:[/bold red] {exc}")
            raise typer.Exit(code=1)

    match = scan_registry.get_finding_by_id(finding_id)
    if not match:
        console.print(f"[bold red][!] Finding '{finding_id}' not found in local scan registry.[/bold red]")
        raise typer.Exit(code=1)
    finding, _ = match
    updated = SafeValidationWorkflow.transition(
        finding=finding,
        target_state=target_state,
        actor=actor,
        notes=notes,
    )
    console.print(f"[bold green][✓][/bold green] Finding {updated.id} transitioned to [cyan]{target_state.value}[/cyan]")
