from unittest.mock import AsyncMock, patch
from uuid import uuid4
from datetime import datetime, timezone
from pathlib import Path
from typer.testing import CliRunner

from cli.ashlynx.main import app as cli_app
from shared.schemas.common import Severity, FindingStatus
from shared.schemas.discovery import ReconSummaryResponse
from shared.schemas.finding import FindingResponse, EndpointSchema, EvidenceSchema
from backend.app.scanner.orchestration.scan_orchestrator import scan_registry

runner = CliRunner()


def make_mock_summary(has_high_finding: bool = False):
    scan_id = uuid4()
    findings = []
    if has_high_finding:
        findings.append(
            FindingResponse(
                id=uuid4(),
                scan_id=scan_id,
                title="Critical API Key Disclosure",
                description="Hardcoded API secret found in response body",
                severity=Severity.HIGH,
                confidence=0.95,
                status=FindingStatus.SUSPECTED,
                cwe_id="CWE-798",
                cvss_score=8.5,
                remediation="Revoke exposed credentials immediately.",
                endpoint=EndpointSchema(url="https://cli.test/config", method="GET"),
                evidence=EvidenceSchema(
                    request="GET /config HTTP/1.1",
                    response="Bearer eyJhbGciOi...",
                    sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                ),
                created_at=datetime.now(timezone.utc),
            )
        )
    return ReconSummaryResponse(
        scan_id=scan_id,
        target_url="https://cli.test",
        status="COMPLETED",
        urls_crawled=3,
        endpoints_discovered=3,
        forms_discovered=0,
        technologies_detected=0,
        crawl_depth_reached=1,
        execution_time_seconds=0.5,
        categories_breakdown={"API": 3},
        technologies=[],
        findings_count=len(findings),
        findings=findings,
    )


def test_cli_scan_help():
    result = runner.invoke(cli_app, ["scan", "--help"])
    assert result.exit_code == 0
    assert "Trigger and monitor web application security scans." in result.output
    assert "--authorized" in result.output
    assert "--profile" in result.output
    assert "--fail-on-findings" in result.output


def test_cli_scan_safety_gate_enforcement():
    result = runner.invoke(cli_app, ["scan", "https://example.com"])
    assert result.exit_code == 2
    assert "SAFETY GATE VIOLATION" in result.output


def test_cli_scan_invalid_profile():
    result = runner.invoke(cli_app, ["scan", "https://example.com", "--authorized", "--profile", "NON_EXISTENT"])
    assert result.exit_code == 2
    assert "Invalid scan profile" in result.output


def test_cli_scan_table_output_success():
    with patch(
        "backend.app.scanner.orchestration.scan_orchestrator.ReconOrchestrator.run",
        new=AsyncMock(return_value=make_mock_summary(has_high_finding=False)),
    ):
        result = runner.invoke(cli_app, ["scan", "https://cli.test", "--authorized", "--profile", "SAFE_MODE"])
        assert result.exit_code == 0
        assert "Scan Execution Summary" in result.output
        assert "Executive Vulnerability Breakdown" in result.output
        assert "Zero security weaknesses detected" in result.output


def test_cli_scan_json_output():
    with patch(
        "backend.app.scanner.orchestration.scan_orchestrator.ReconOrchestrator.run",
        new=AsyncMock(return_value=make_mock_summary(has_high_finding=True)),
    ):
        result = runner.invoke(
            cli_app,
            ["scan", "https://cli.test", "--authorized", "--format", "json"],
        )
        assert result.exit_code == 0
        assert '"target_url": "https://cli.test"' in result.output
        assert "Critical API Key Disclosure" in result.output


def test_cli_scan_export_to_file(tmp_path: Path):
    output_file = tmp_path / "cli_report.html"
    with patch(
        "backend.app.scanner.orchestration.scan_orchestrator.ReconOrchestrator.run",
        new=AsyncMock(return_value=make_mock_summary(has_high_finding=True)),
    ):
        result = runner.invoke(
            cli_app,
            ["scan", "https://cli.test", "--authorized", "--output", str(output_file)],
        )
        assert result.exit_code == 0
        assert "Report successfully saved to" in result.output
        assert output_file.exists()
        assert "<!DOCTYPE html>" in output_file.read_text(encoding="utf-8")


def test_cli_scan_ci_fail_on_findings():
    with patch(
        "backend.app.scanner.orchestration.scan_orchestrator.ReconOrchestrator.run",
        new=AsyncMock(return_value=make_mock_summary(has_high_finding=True)),
    ):
        result = runner.invoke(
            cli_app,
            ["scan", "https://cli.test", "--authorized", "--fail-on-findings"],
        )
        assert result.exit_code == 1
        assert "CI Gate Failed" in result.output
