import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from backend.app.main import app
from backend.app.models.entities import (
    CorrelationGroupRecord,
    FindingIntelligenceRecord,
    ValidationHistoryRecord,
)
from backend.app.reporting.html_report import HTMLReportGenerator
from backend.app.reporting.json_report import JSONReportGenerator
from backend.app.reporting.markdown_report import MarkdownReportGenerator
from backend.app.scanner.intelligence.validation import SafeValidationWorkflow
from backend.app.scanner.orchestration.scan_orchestrator import ScanOrchestrator, scan_registry
from cli.ashlynx.main import app as cli_app
from shared.schemas.common import FindingStatus, ScanProfile, Severity
from shared.schemas.discovery import ReconSummaryResponse, TechnologyObservationSchema
from shared.schemas.finding import EndpointSchema, EvidenceSchema, FindingResponse
from shared.schemas.intelligence import ValidationState

client = TestClient(app)
cli_runner = CliRunner()


@pytest.fixture(autouse=True)
def reset_scan_registry():
    scan_registry.clear()
    yield
    scan_registry.clear()


def _seed_completed_scan(target_url: str = "https://target-a.example.com", target_id=None):
    scan_id = uuid4()
    target_id = target_id or uuid4()

    f1 = FindingResponse(
        id=uuid4(),
        scan_id=scan_id,
        target_id=target_id,
        title="Reflected Cross-Site Scripting (HTML Context)",
        description="Unescaped canary <script>alert('xss')</script>",
        cwe_id="CWE-79",
        owasp_category="A03:2021 - Injection",
        severity=Severity.HIGH,
        cvss_score=7.5,
        status=FindingStatus.VERIFIED,
        confidence=0.95,
        remediation="HTML encode parameter output.",
        endpoint=EndpointSchema(url=f"{target_url}/search?q=test", method="GET", parameter="q"),
        evidence=EvidenceSchema(
            request="GET /search?q=ashlynx HTTP/1.1\r\nAuthorization: Bearer secret_token_xyz",
            response="HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<div>ashlynx</div>",
            sha256_hash="a" * 64,
            probe_type="active_probe",
        ),
        created_at="2026-11-25T12:00:00Z",
    )
    f2 = FindingResponse(
        id=uuid4(),
        scan_id=scan_id,
        target_id=target_id,
        title="Missing Content-Security-Policy Header",
        description="CSP absent",
        cwe_id="CWE-693",
        owasp_category="A05:2021 - Security Misconfiguration",
        severity=Severity.MEDIUM,
        cvss_score=5.0,
        status=FindingStatus.DETECTED,
        confidence=0.85,
        remediation="Configure CSP header.",
        endpoint=EndpointSchema(
            url=f"{target_url}/search",
            method="GET",
            headers={"evidence_rule": "PASSIVE-HDR-CSP-MISSING"},
        ),
        evidence=EvidenceSchema(
            request="GET /search HTTP/1.1",
            response="HTTP/1.1 200 OK\r\nContent-Type: text/html",
            sha256_hash="b" * 64,
            probe_type="passive_analysis",
        ),
        created_at="2026-11-25T12:00:00Z",
    )

    mock_recon = ReconSummaryResponse(
        scan_id=scan_id,
        target_url=target_url,
        status="COMPLETED",
        urls_crawled=5,
        endpoints_discovered=5,
        forms_discovered=1,
        technologies_detected=1,
        crawl_depth_reached=2,
        execution_time_seconds=1.1,
        categories_breakdown={"PAGE": 5},
        technologies=[
            TechnologyObservationSchema(
                scan_id=scan_id,
                technology_name="Nginx",
                category="web-server",
                version="1.18.0",
                confidence=0.9,
                detection_source="HTTP Headers",
            )
        ],
        findings_count=2,
        findings=[f1, f2],
    )
    return scan_id, target_id, mock_recon


@pytest.mark.asyncio
async def test_scan_orchestrator_end_to_end_avive_integration_and_reports():
    scan_id, target_id, mock_recon = _seed_completed_scan()
    orch = ScanOrchestrator(
        target_url="https://target-a.example.com",
        scan_id=scan_id,
        target_id=target_id,
        profile=ScanProfile.QUICK_ASSESSMENT,
        asset_criticality=4.0,
    )
    scan_registry.register_orchestrator(orch)

    with patch(
        "backend.app.scanner.orchestration.scan_orchestrator.ReconOrchestrator.run",
        new=AsyncMock(return_value=mock_recon),
    ):
        report = await orch.run()
        scan_registry.store_report(report)

    assert report.intelligence_summary is not None
    assert report.intelligence_summary.total_raw_findings == 2
    assert len(report.findings) == 2

    # Check both findings enriched with AVIVE and secret redacted
    for f in report.findings:
        assert f.intelligence is not None
        assert f.intelligence.contextual_risk.asset_criticality_used == 4.0
        if f.evidence:
            assert "secret_token_xyz" not in f.evidence.request

    # Check XSS finding validated and correlated with CSP
    xss_f = next(f for f in report.findings if f.cwe_id == "CWE-79")
    assert xss_f.intelligence.validation_state == ValidationState.VALIDATED
    assert xss_f.intelligence.confidence_assessment.level.value == "HIGH"
    assert len(xss_f.intelligence.related_finding_ids) == 1

    # Verify Reports preserve XSS safety & include AVIVE enrichment
    html_out = HTMLReportGenerator().generate(report)
    assert "<script>alert('xss')</script>" not in html_out
    assert "&lt;script&gt;alert" in html_out
    assert "Context Priority:" in html_out

    md_out = MarkdownReportGenerator().generate(report)
    assert "AVIVE Confidence:" in md_out
    assert "Secure Implementation Guidance:" in md_out

    json_out = JSONReportGenerator().generate(report)
    parsed = json.loads(json_out)
    assert "intelligence_summary" in parsed
    assert parsed["findings"][0]["intelligence"]["fingerprint"]


@pytest.mark.asyncio
async def test_api_findings_endpoints_filtering_and_risk_recalculation():
    scan_id, target_id, mock_recon = _seed_completed_scan()
    orch = ScanOrchestrator(
        target_url="https://target-a.example.com",
        scan_id=scan_id,
        target_id=target_id,
        profile=ScanProfile.QUICK_ASSESSMENT,
    )
    scan_registry.register_orchestrator(orch)
    with patch(
        "backend.app.scanner.orchestration.scan_orchestrator.ReconOrchestrator.run",
        new=AsyncMock(return_value=mock_recon),
    ):
        report = await orch.run()
        scan_registry.store_report(report)

    # 1. GET /api/v1/findings/ with filters
    resp = client.get(f"/api/v1/findings/?scan_id={scan_id}&confidence_level=HIGH")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 2  # Both XSS (verified) and CSP (high deterministic passive) have HIGH conf

    resp_cwe = client.get(f"/api/v1/findings/?scan_id={scan_id}&cwe_id=CWE-79")
    assert resp_cwe.status_code == 200
    assert resp_cwe.json()["total"] == 1
    finding_id = resp_cwe.json()["items"][0]["id"]

    # 2. GET /api/v1/findings/{id}/relationships
    rel_resp = client.get(f"/api/v1/findings/{finding_id}/relationships")
    assert rel_resp.status_code == 200
    assert len(rel_resp.json()["data"]["related_findings"]) == 1

    # 3. GET /api/v1/scans/{id}/intelligence & POST /risk-config
    intel_resp = client.get(f"/api/v1/scans/{scan_id}/intelligence")
    assert intel_resp.status_code == 200
    assert intel_resp.json()["data"]["total_raw_findings"] == 2

    risk_resp = client.post(
        f"/api/v1/scans/{scan_id}/risk-config",
        json={"asset_criticality": 5.0, "notes": "Tier 0 production"},
    )
    assert risk_resp.status_code == 200
    updated_finding = client.get(f"/api/v1/findings/{finding_id}").json()["data"]
    assert updated_finding["intelligence"]["contextual_risk"]["asset_criticality_used"] == 5.0

    # 4. POST /api/v1/findings/{id}/remediation
    rem_resp = client.post(
        f"/api/v1/findings/{finding_id}/remediation",
        json={"remediation_status": "VERIFIED_FIXED", "actor": "dev_lead"},
    )
    assert rem_resp.status_code == 200
    assert rem_resp.json()["data"]["intelligence"]["validation_state"] == "RESOLVED"


@pytest.mark.asyncio
async def test_security_controls_idor_ssrf_authorization_and_pagination():
    scan_a, target_a, recon_a = _seed_completed_scan("https://target-a.example.com", uuid4())
    orch_a = ScanOrchestrator(target_url="https://target-a.example.com", scan_id=scan_a, target_id=target_a)
    scan_registry.register_orchestrator(orch_a)
    with patch(
        "backend.app.scanner.orchestration.scan_orchestrator.ReconOrchestrator.run",
        new=AsyncMock(return_value=recon_a),
    ):
        rep_a = await orch_a.run()
        scan_registry.store_report(rep_a)

    finding_a_id = rep_a.findings[0].id
    other_target_id = uuid4()
    other_scan_id = uuid4()

    # 1. Cross-target IDOR blocked
    idor_resp = client.get(f"/api/v1/findings/{finding_a_id}?target_id={other_target_id}")
    assert idor_resp.status_code == 403
    assert "isolation" in idor_resp.json()["detail"].lower()

    # 2. Cross-scan validation manipulation blocked
    val_idor = client.post(
        f"/api/v1/findings/{finding_a_id}/validate",
        json={"target_state": "FALSE_POSITIVE", "scan_id": str(other_scan_id)},
    )
    assert val_idor.status_code == 403

    # 3. Live safe revalidation without authorized=True blocked
    unauth_reval = client.post(
        f"/api/v1/findings/{finding_a_id}/validate",
        json={"target_state": "VALIDATED", "run_safe_revalidation": True, "authorized": False},
    )
    assert unauth_reval.status_code == 403
    assert "Safety Gate Violation" in unauth_reval.json()["detail"]

    # 4. Safe revalidation strictly enforces ScopeGate against private/metadata targets
    ssrf_finding = rep_a.findings[1]
    ssrf_finding.endpoint.url = "http://169.254.169.254/latest/meta-data/"
    with pytest.raises(PermissionError) as exc_info:
        await SafeValidationWorkflow.run_safe_revalidation(
            finding=ssrf_finding,
            target_base_url="https://target-a.example.com",
            authorized=True,
            allow_private_ips=False,
        )
    assert "ScopeGate blocked" in str(exc_info.value)

    # 5. Pagination resource exhaustion safeguard (>100 rejected)
    exhaust_resp = client.get("/api/v1/findings/?page_size=5000")
    assert exhaust_resp.status_code == 422


@pytest.mark.asyncio
async def test_cli_findings_commands_and_path_traversal_block(tmp_path: Path):
    scan_id, target_id, mock_recon = _seed_completed_scan()
    orch = ScanOrchestrator(target_url="https://target-a.example.com", scan_id=scan_id, target_id=target_id)
    scan_registry.register_orchestrator(orch)
    with patch(
        "backend.app.scanner.orchestration.scan_orchestrator.ReconOrchestrator.run",
        new=AsyncMock(return_value=mock_recon),
    ):
        report = await orch.run()
        scan_registry.store_report(report)

    report_path = tmp_path / "scan_report.json"
    report_path.write_text(report.model_dump_json(), encoding="utf-8")

    # CLI list from exported JSON
    res_list = cli_runner.invoke(cli_app, ["findings", "list", "--input", str(report_path), "--confidence", "HIGH", "--format", "json"])
    assert res_list.exit_code == 0
    items = json.loads(res_list.stdout)
    assert len(items) == 2

    # CLI export safe destination
    export_dest = tmp_path / "enriched.json"
    res_export = cli_runner.invoke(cli_app, ["findings", "export", "--input", str(report_path), "--output", str(export_dest)])
    assert res_export.exit_code == 0
    assert export_dest.exists()

    # Path traversal blocked in export
    res_traversal = cli_runner.invoke(cli_app, ["findings", "export", "--input", str(report_path), "--output", "../../etc/passwd"])
    assert res_traversal.exit_code != 0


def test_phase5_orm_models_instantiation():
    grp = CorrelationGroupRecord(
        scan_id=uuid4(),
        group_key="corr-dupl-abc123",
        relationship_type="DUPLICATE",
        primary_finding_id=uuid4(),
        correlation_confidence=0.98,
        explanation="Duplicate detection",
        shared_attributes=["cwe:CWE-79"],
    )
    intel_rec = FindingIntelligenceRecord(
        finding_id=uuid4(),
        scan_id=uuid4(),
        fingerprint="abc123def456",
        vulnerability_category="XSS",
        confidence_level="HIGH",
        confidence_score=0.92,
        confidence_explanation="Verified",
        validation_state="VALIDATED",
        contextual_priority="HIGH",
        contextual_score=78.5,
    )
    hist = ValidationHistoryRecord(
        finding_id=intel_rec.finding_id,
        from_state="DETECTED",
        to_state="VALIDATED",
        actor="analyst",
        validation_method="manual_review",
    )
    assert grp.relationship_type == "DUPLICATE"
    assert intel_rec.contextual_priority == "HIGH"
    assert hist.to_state == "VALIDATED"
