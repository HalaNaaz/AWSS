import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from uuid import uuid4
from datetime import datetime, timezone

from shared.schemas.common import ScanProfile, ScanStatus, Severity, FindingStatus
from shared.schemas.discovery import ReconSummaryResponse, DiscoveredEndpointCreate, EndpointCategory, DiscoveryMethod
from shared.schemas.finding import FindingResponse, EndpointSchema
from backend.app.scanner.orchestration.scan_orchestrator import ScanOrchestrator
from backend.app.scanner.active.models import ActiveFinding


@pytest.mark.asyncio
async def test_end_to_end_active_scan_orchestration():
    scan_id = uuid4()
    target_url = "https://app.test.local"

    # Simulated reconnaissance summary with discovered endpoint containing query parameter
    endpoint = DiscoveredEndpointCreate(
        scan_id=scan_id,
        url="https://app.test.local/items?cat=tech",
        normalized_url="https://app.test.local/items?cat=tech",
        method="GET",
        discovery_method=DiscoveryMethod.CRAWLER,
        endpoint_category=EndpointCategory.PAGE,
        crawl_depth=1,
    )

    passive_finding = FindingResponse(
        id=uuid4(),
        scan_id=scan_id,
        title="Missing CSP",
        description="CSP header is absent",
        cwe_id="CWE-693",
        severity=Severity.MEDIUM,
        cvss_score=5.0,
        status=FindingStatus.DETECTED,
        confidence=0.9,
        remediation="Add CSP header",
        endpoint=EndpointSchema(url=target_url, method="GET"),
        created_at=datetime.now(timezone.utc),
    )

    mock_recon_summary = ReconSummaryResponse(
        scan_id=scan_id,
        target_url=target_url,
        status="COMPLETED",
        urls_crawled=2,
        endpoints_discovered=2,
        forms_discovered=0,
        technologies_detected=0,
        crawl_depth_reached=1,
        execution_time_seconds=1.0,
        categories_breakdown={"PAGE": 2},
        technologies=[],
        findings_count=1,
        findings=[passive_finding],
    )

    active_finding = ActiveFinding(
        rule_id="ACT-SQLI-ERROR",
        title="SQL Error in cat parameter",
        description="Database error was provoked",
        cwe_id="CWE-89",
        owasp_category="A03:2021",
        severity=Severity.HIGH,
        cvss_score=8.5,
        status=FindingStatus.SUSPECTED,
        confidence=0.85,
        url="https://app.test.local/items?cat=tech",
        parameter="cat",
        remediation="Use parameterized queries",
        detection_module="ACT-SQLI-ANALYZER",
    )

    orchestrator = ScanOrchestrator(
        target_url=target_url,
        scan_id=scan_id,
        profile=ScanProfile.SAFE_ACTIVE,
    )

    with patch(
        "backend.app.scanner.orchestration.scan_orchestrator.ReconOrchestrator.run",
        new=AsyncMock(return_value=mock_recon_summary),
    ) as mock_recon_run:
        # Give recon_orchestrator discovered endpoints
        def setup_recon_endpoints():
            orchestrator._recon_orchestrator.discovered_endpoints = [endpoint]
            return mock_recon_summary

        mock_recon_run.side_effect = setup_recon_endpoints

        with patch(
            "backend.app.scanner.active.engine.ActiveDetectionEngine.run",
            new=AsyncMock(return_value=[active_finding]),
        ):
            report = await orchestrator.run()

            assert orchestrator.status == ScanStatus.COMPLETED
            assert report.status == ScanStatus.COMPLETED
            assert report.profile == ScanProfile.SAFE_ACTIVE

            # Both passive and active findings should be present in report
            assert len(report.findings) == 2
            titles = [f.title for f in report.findings]
            assert "Missing CSP" in titles
            assert "SQL Error in cat parameter" in titles

            # Severity breakdown reflects both
            assert report.severity_summary.high == 1
            assert report.severity_summary.medium == 1
            assert report.severity_summary.total == 2
