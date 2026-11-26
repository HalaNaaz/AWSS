from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from backend.app.main import app
from backend.app.reporting.markdown_report import MarkdownReportGenerator
from backend.app.scanner.discovery.engine import AttackSurfaceIntelligenceEngine
from backend.app.scanner.intelligence.planner import IntelligentScanPlanner
from backend.app.scanner.orchestration.scan_orchestrator import ScanOrchestrator, scan_registry
from backend.app.scanner.scope.scope_gate import ScopeGate
from cli.ashlynx.main import app as cli_app
from shared.schemas.common import FindingStatus, ScanProfile, ScanStatus, Severity
from shared.schemas.discovery import ReconSummaryResponse
from shared.schemas.finding import EndpointSchema, EvidenceSchema, FindingResponse

client = TestClient(app)
cli_runner = CliRunner()


@pytest.fixture(autouse=True)
def clean_registry():
    scan_registry.clear()
    yield
    scan_registry.clear()


def _build_mock_recon(scan_id, target_url: str):
    f1 = FindingResponse(
        id=uuid4(),
        scan_id=scan_id,
        title="Missing CSP Header",
        cwe_id="CWE-693",
        severity=Severity.MEDIUM,
        cvss_score=5.0,
        status=FindingStatus.DETECTED,
        confidence=0.85,
        endpoint=EndpointSchema(url=f"{target_url}/", method="GET"),
        evidence=EvidenceSchema(
            request="GET / HTTP/1.1",
            response="HTTP/1.1 200 OK",
            sha256_hash="c" * 64,
            probe_type="passive_analysis",
        ),
        created_at="2026-11-26T00:00:00Z",
    )
    return ReconSummaryResponse(
        scan_id=scan_id,
        target_url=target_url,
        status="COMPLETED",
        urls_crawled=4,
        endpoints_discovered=4,
        forms_discovered=1,
        technologies_detected=0,
        crawl_depth_reached=2,
        execution_time_seconds=0.5,
        categories_breakdown={"PAGE": 4},
        technologies=[],
        findings_count=1,
        findings=[f1],
    )


@pytest.mark.asyncio
async def test_phase6_orchestrator_api_cli_and_markdown_integration():
    scan_id = uuid4()
    target_url = "https://target.example.com"
    orch = ScanOrchestrator(
        target_url=target_url,
        scan_id=scan_id,
        profile=ScanProfile.QUICK_ASSESSMENT,
    )
    scan_registry.register_orchestrator(orch)
    mock_recon = _build_mock_recon(scan_id, target_url)

    with patch(
        "backend.app.scanner.orchestration.scan_orchestrator.ReconOrchestrator.run",
        new=AsyncMock(return_value=mock_recon),
    ):
        report = await orch.run()
        scan_registry.store_report(report)

    assert report.scan_plan is not None
    assert report.context_assessment is not None
    assert report.security_coverage is not None
    assert report.execution_reliability is not None
    assert report.evidence_intelligence is not None

    # API Endpoints
    for suffix in ("plan", "context-assessment", "coverage", "reliability", "evidence-intelligence"):
        resp = client.get(f"/api/v1/scans/{scan_id}/{suffix}")
        assert resp.status_code == 200, f"Failed GET /scans/{scan_id}/{suffix}"
        assert resp.json()["success"] is True

    overview = client.get("/api/v1/analytics/overview")
    assert overview.status_code == 200
    assert overview.json()["data"]["total_scans_analyzed"] == 1

    cmp_resp = client.get(f"/api/v1/analytics/compare?baseline_scan_id={scan_id}&current_scan_id={scan_id}")
    assert cmp_resp.status_code == 200
    cmp_data = cmp_resp.json()["data"]
    assert cmp_data["persisting_findings_count"] == 1
    assert cmp_data["new_findings_count"] == 0
    assert cmp_data["resolved_findings_count"] == 0
    assert "Self-Comparison" in cmp_data["summary"]

    # Missing baseline / current comparison returns 404
    missing_id = uuid4()
    assert client.get(f"/api/v1/analytics/compare?baseline_scan_id={missing_id}&current_scan_id={scan_id}").status_code == 404
    assert client.get(f"/api/v1/analytics/compare?baseline_scan_id={scan_id}&current_scan_id={missing_id}").status_code == 404

    # Whitespace-only findings query parameters do not erase results
    ws_findings = client.get("/api/v1/findings/?cwe_id=%20%20&search=%20%20")
    assert ws_findings.status_code == 200
    assert len(ws_findings.json()["items"]) == 1

    # Markdown Report contains OWASP Coverage
    md = MarkdownReportGenerator().generate(report)
    assert "OWASP Top 10:2021 Security Coverage Intelligence" in md

    # CLI Analytics
    cli_res = cli_runner.invoke(cli_app, ["analytics", "overview", "--format", "json"])
    assert cli_res.exit_code == 0
    assert '"total_scans_analyzed": 1' in cli_res.stdout


def test_phase6_security_duplicate_job_guard_and_scopegate_planner():
    # 1. Duplicate running scan job blocked with 409 Conflict
    scan_id = uuid4()
    orch = ScanOrchestrator(target_url="https://target.example.com", scan_id=scan_id, profile=ScanProfile.SAFE_ACTIVE)
    orch.status = ScanStatus.RUNNING
    scan_registry.register_orchestrator(orch)

    dup_resp = client.post(
        "/api/v1/scans/",
        json={"target_url": "https://target.example.com", "profile": "SAFE_ACTIVE"},
    )
    assert dup_resp.status_code == 409

    # 2. Planner strictly blocks SSRF / out-of-scope URLs even if injected into discovery
    gate = ScopeGate(target_base_url="https://target.example.com", allow_private_ips=False)
    disc = AttackSurfaceIntelligenceEngine("https://target.example.com", gate, uuid4())
    # Force-add an out-of-scope/SSRF endpoint directly to bypass add_endpoint filter
    from shared.schemas.discovery import DiscoveredEndpointCreate, DiscoveryMethod, EndpointCategory
    disc.endpoint_engine._endpoints["http://169.254.169.254/latest/meta-data:GET"] = DiscoveredEndpointCreate(
        scan_id=disc.scan_id,
        url="http://169.254.169.254/latest/meta-data",
        normalized_url="http://169.254.169.254/latest/meta-data",
        method="GET",
        discovery_method=DiscoveryMethod.CRAWLER,
        endpoint_category=EndpointCategory.PAGE,
    )
    plan = IntelligentScanPlanner.build_plan(
        scan_id=disc.scan_id,
        target_url="https://target.example.com",
        profile=ScanProfile.SAFE_ACTIVE,
        scope_gate=gate,
        discovery_engine=disc,
    )
    assert all("169.254.169.254" not in p.url for p in plan.planned_checks)
    assert any("169.254.169.254" in s.url and "ScopeGate" in s.reason for s in plan.skipped_checks)
