from uuid import UUID
from fastapi import APIRouter, HTTPException, Query

from backend.app.scanner.intelligence.analytics import SecurityAnalyticsEngine
from backend.app.scanner.orchestration.scan_orchestrator import scan_registry
from shared.schemas.common import APIResponse
from shared.schemas.phase6 import ScanAnalyticsSchema, ScanComparisonSchema

router = APIRouter()


@router.get("/overview", response_model=APIResponse[ScanAnalyticsSchema])
async def get_security_analytics_overview() -> APIResponse[ScanAnalyticsSchema]:
    """Returns real-data security analytics aggregated across all executed scans."""
    reports = scan_registry.list_reports()
    analytics = SecurityAnalyticsEngine.compute_analytics(reports)
    return APIResponse(success=True, data=analytics)


@router.get("/compare", response_model=APIResponse[ScanComparisonSchema])
async def compare_two_scans(
    baseline_scan_id: UUID = Query(..., description="Baseline scan UUID"),
    current_scan_id: UUID = Query(..., description="Current/target scan UUID"),
) -> APIResponse[ScanComparisonSchema]:
    """Compares findings and coverage between two completed scans using deterministic fingerprints."""
    baseline = scan_registry.get_report(baseline_scan_id)
    if not baseline:
        raise HTTPException(status_code=404, detail=f"Baseline scan '{baseline_scan_id}' not found or not completed.")

    current = scan_registry.get_report(current_scan_id)
    if not current:
        raise HTTPException(status_code=404, detail=f"Current scan '{current_scan_id}' not found or not completed.")

    comparison = SecurityAnalyticsEngine.compare_scans(baseline=baseline, current=current)
    return APIResponse(success=True, data=comparison)
