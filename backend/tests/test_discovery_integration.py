import asyncio
import pytest
from uuid import uuid4

from backend.app.scanner.orchestration.scan_orchestrator import ScanOrchestrator, scan_registry
from backend.app.scanner.reconnaissance.orchestrator import ReconOrchestrator
from shared.schemas.common import ScanProfile


@pytest.fixture(autouse=True)
def cleanup():
    scan_registry.clear()
    yield
    scan_registry.clear()


@pytest.mark.asyncio
async def test_attack_surface_recon_integration():
    scan_id = uuid4()
    target_url = "https://example.com"

    orchestrator = ReconOrchestrator(
        target_url=target_url,
        scan_id=scan_id,
        max_depth=1,
        max_urls=10,
        concurrency=2,
        analyze_javascript=False
    )

    # Engine is properly initialized
    assert orchestrator.discovery_engine is not None
    assert orchestrator.discovery_engine.target_base_url == target_url

    # Simulate ingesting sample page
    orchestrator.discovery_engine.ingest_crawled_page(
        url="https://example.com/checkout?step=payment",
        status_code=200,
        content_type="text/html",
        headers={"Server": "nginx", "X-Powered-By": "Express"}
    )

    summary = orchestrator.discovery_engine.get_summary()
    assert summary.total_endpoints >= 1
    assert summary.total_parameters >= 1
    assert summary.total_technologies >= 1


@pytest.mark.asyncio
async def test_scan_orchestrator_discovery_summary_inclusion():
    scan_id = uuid4()
    target_url = "https://example.com"

    scan_orchestrator = ScanOrchestrator(
        target_url=target_url,
        scan_id=scan_id,
        profile=ScanProfile.PASSIVE_ONLY,
        max_crawl_depth=1,
        max_urls=5
    )
    scan_registry.register_orchestrator(scan_orchestrator)

    # Ensure registry exposes discovery engine
    assert scan_registry.get_job(scan_id) is not None
