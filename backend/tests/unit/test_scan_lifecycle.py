import asyncio
import pytest
from unittest.mock import AsyncMock, patch
from uuid import uuid4
from datetime import datetime, timezone

from shared.schemas.common import ScanProfile, ScanStatus, Severity, FindingStatus
from shared.schemas.discovery import ReconSummaryResponse, TechnologyObservationSchema
from shared.schemas.finding import FindingResponse, EndpointSchema, EvidenceSchema
from shared.schemas.scan import ScanJobResponse
from backend.app.scanner.orchestration.scan_orchestrator import (
    ScanOrchestrator,
    ScanLifecycleRegistry,
)


@pytest.fixture
def mock_recon_summary():
    scan_id = uuid4()
    findings = [
        FindingResponse(
            id=uuid4(),
            scan_id=scan_id,
            title="Missing HSTS Header",
            description="Strict-Transport-Security header is missing.",
            severity=Severity.MEDIUM,
            confidence=0.9,
            status=FindingStatus.SUSPECTED,
            cwe_id="CWE-319",
            cvss_score=5.0,
            remediation="Configure Strict-Transport-Security header.",
            endpoint=EndpointSchema(url="https://example.com", method="GET"),
            evidence=EvidenceSchema(
                request="GET / HTTP/1.1\r\nHost: example.com",
                response="HTTP/1.1 200 OK\r\nContent-Type: text/html",
                sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            created_at=datetime.now(timezone.utc),
        )
    ]
    technologies = [
        TechnologyObservationSchema(
            scan_id=scan_id,
            technology_name="Cloudflare",
            category="CDN",
            version=None,
            confidence=0.9,
            detection_source="HTTP Headers",
        )
    ]
    return ReconSummaryResponse(
        scan_id=scan_id,
        target_url="https://example.com",
        status="COMPLETED",
        urls_crawled=10,
        endpoints_discovered=8,
        forms_discovered=2,
        technologies_detected=1,
        crawl_depth_reached=2,
        execution_time_seconds=3.5,
        categories_breakdown={"API": 3, "PAGE": 5},
        technologies=technologies,
        findings_count=1,
        findings=findings,
    )


def test_scan_orchestrator_initial_state_and_profile_presets():
    orchestrator = ScanOrchestrator(
        target_url="https://target.local",
        profile=ScanProfile.PASSIVE_DISCOVERY,
    )
    assert orchestrator.status == ScanStatus.QUEUED
    assert orchestrator.max_crawl_depth == 2
    assert orchestrator.max_urls == 100
    assert orchestrator.concurrency == 3
    assert orchestrator.rate_limit_rps == 5.0

    full_orch = ScanOrchestrator(
        target_url="https://target.local",
        profile=ScanProfile.FULL_ASSESSMENT,
    )
    assert full_orch.max_crawl_depth == 5
    assert full_orch.max_urls == 1000
    assert full_orch.concurrency == 8
    assert full_orch.rate_limit_rps == 15.0

    custom_orch = ScanOrchestrator(
        target_url="https://target.local",
        profile=ScanProfile.PASSIVE_DISCOVERY,
        max_crawl_depth=7,
        max_urls=250,
        concurrency=12,
        rate_limit_rps=25.0,
    )
    assert custom_orch.max_crawl_depth == 7
    assert custom_orch.max_urls == 250
    assert custom_orch.concurrency == 12
    assert custom_orch.rate_limit_rps == 25.0


def test_scan_orchestrator_empty_target_failure():
    orchestrator = ScanOrchestrator(target_url="")
    report = asyncio.run(orchestrator.run())

    assert orchestrator.status == ScanStatus.FAILED
    assert report.status == ScanStatus.FAILED
    assert "Target URL must not be empty" in orchestrator.error_message


def test_scan_orchestrator_cancellation_before_run():
    orchestrator = ScanOrchestrator(target_url="https://target.local")
    orchestrator.cancel()

    assert orchestrator.is_cancelled is True
    report = asyncio.run(orchestrator.run())

    assert orchestrator.status == ScanStatus.CANCELLED
    assert report.status == ScanStatus.CANCELLED
    assert report.urls_crawled == 0


@pytest.mark.asyncio
async def test_scan_orchestrator_successful_execution(mock_recon_summary):
    orchestrator = ScanOrchestrator(
        target_url="https://example.com",
        profile=ScanProfile.QUICK_ASSESSMENT,
    )

    with patch(
        "backend.app.scanner.orchestration.scan_orchestrator.ReconOrchestrator.run",
        new=AsyncMock(return_value=mock_recon_summary),
    ):
        report = await orchestrator.run()

        assert orchestrator.status == ScanStatus.COMPLETED
        assert report.status == ScanStatus.COMPLETED
        assert report.target_url == "https://example.com"
        assert report.urls_crawled == 10
        assert report.endpoints_discovered == 8
        assert len(report.findings) == 1
        assert report.severity_summary.medium == 1
        assert len(report.technologies) == 1
        assert orchestrator.duration_seconds >= 0.0

        job_resp = orchestrator.get_job_response()
        assert job_resp.status == ScanStatus.COMPLETED
        assert job_resp.findings_count == 1
        assert job_resp.urls_crawled == 10


@pytest.mark.asyncio
async def test_scan_orchestrator_handles_exception():
    orchestrator = ScanOrchestrator(target_url="https://example.com")

    with patch(
        "backend.app.scanner.orchestration.scan_orchestrator.ReconOrchestrator.run",
        new=AsyncMock(side_effect=RuntimeError("Network interface unreachable")),
    ):
        report = await orchestrator.run()

        assert orchestrator.status == ScanStatus.FAILED
        assert report.status == ScanStatus.FAILED
        assert "Network interface unreachable" in orchestrator.error_message


def test_scan_lifecycle_registry():
    registry = ScanLifecycleRegistry()
    scan_id = uuid4()

    orchestrator = ScanOrchestrator(
        target_url="https://registry-test.com",
        scan_id=scan_id,
        profile=ScanProfile.SAFE_MODE,
    )
    registry.register_orchestrator(orchestrator)

    job = registry.get_job(scan_id)
    assert job is not None
    assert job.id == scan_id
    assert job.status == ScanStatus.QUEUED

    all_jobs = registry.list_jobs()
    assert len(all_jobs) == 1
    assert all_jobs[0].id == scan_id

    success = registry.cancel_scan(scan_id)
    assert success is True
    assert registry.get_job(scan_id).status == ScanStatus.CANCELLED

    registry.clear()
    assert len(registry.list_jobs()) == 0
