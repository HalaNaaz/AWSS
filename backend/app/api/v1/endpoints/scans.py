from typing import List, Optional
from uuid import UUID, uuid4
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Query, status, BackgroundTasks, Response
from shared.schemas.common import APIResponse, PaginatedResponse, ScanStatus, Severity
from shared.schemas.scan import ScanJobCreate, ScanJobResponse
from shared.schemas.finding import FindingResponse
from shared.schemas.intelligence import (
    ConfidenceLevel,
    ContextualPriority,
    RiskConfigUpdateRequest,
    ScanIntelligenceSummarySchema,
    ValidationState,
)
from shared.schemas.report import ReportFormat
from backend.app.api.v1.endpoints.findings import filter_findings_collection
from backend.app.scanner.orchestration.scan_orchestrator import (
    ScanOrchestrator,
    scan_registry,
)
from backend.app.reporting.manager import ReportManager

router = APIRouter()
report_manager = ReportManager()


async def _run_scan_background(orchestrator: ScanOrchestrator) -> None:
    """Executes scan orchestrator and registers resulting unified report."""
    report = await orchestrator.run()
    scan_registry.store_report(report)


@router.post("/", response_model=APIResponse[ScanJobResponse], status_code=status.HTTP_201_CREATED)
async def create_scan_job(
    job_in: ScanJobCreate,
    background_tasks: BackgroundTasks,
    run_sync: bool = Query(False, description="Execute synchronously and wait for completion (for testing/automation)"),
) -> APIResponse[ScanJobResponse]:
    """Registers and queues a new scan job, executing discovery and passive analysis."""
    scan_id = uuid4()
    target_url = job_in.target_url or ""

    orchestrator = ScanOrchestrator(
        target_url=target_url,
        scan_id=scan_id,
        target_id=job_in.target_id,
        profile=job_in.profile,
        max_crawl_depth=job_in.max_crawl_depth,
        max_urls=job_in.max_urls,
        concurrency=job_in.concurrency,
        rate_limit_rps=job_in.rate_limit_rps,
        asset_criticality=job_in.asset_criticality,
    )
    scan_registry.register_orchestrator(orchestrator)

    if run_sync and target_url:
        report = await orchestrator.run()
        scan_registry.store_report(report)
        job_response = orchestrator.get_job_response()
    elif target_url:
        background_tasks.add_task(_run_scan_background, orchestrator)
        job_response = orchestrator.get_job_response()
    else:
        job_response = orchestrator.get_job_response()

    return APIResponse(
        success=True,
        message="Scan job registered and queued successfully.",
        data=job_response,
    )


@router.get("/", response_model=APIResponse[List[ScanJobResponse]])
async def list_scans() -> APIResponse[List[ScanJobResponse]]:
    """Lists all registered scan jobs."""
    jobs = scan_registry.list_jobs()
    return APIResponse(success=True, data=jobs)


@router.get("/{scan_id}", response_model=APIResponse[ScanJobResponse])
async def get_scan_status(scan_id: UUID) -> APIResponse[ScanJobResponse]:
    """Retrieves current execution status of a scan job."""
    job = scan_registry.get_job(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Scan job '{scan_id}' not found.")
    return APIResponse(success=True, data=job)


@router.post("/{scan_id}/cancel", response_model=APIResponse[ScanJobResponse])
async def cancel_scan_job(scan_id: UUID) -> APIResponse[ScanJobResponse]:
    """Cancels an active or queued scan job."""
    job = scan_registry.get_job(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Scan job '{scan_id}' not found.")
    scan_registry.cancel_scan(scan_id)
    updated_job = scan_registry.get_job(scan_id)
    return APIResponse(success=True, message="Scan job cancelled.", data=updated_job)


@router.get("/{scan_id}/findings", response_model=APIResponse[List[FindingResponse]])
async def get_scan_findings(
    scan_id: UUID,
    severity: Optional[Severity] = Query(None),
    confidence_level: Optional[ConfidenceLevel] = Query(None),
    validation_state: Optional[ValidationState] = Query(None),
    contextual_priority: Optional[ContextualPriority] = Query(None),
    correlation_group_id: Optional[str] = Query(None),
    include_duplicates: bool = Query(True),
) -> APIResponse[List[FindingResponse]]:
    """Retrieves all security findings associated with a scan with optional AVIVE intelligence filters."""
    job = scan_registry.get_job(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Scan job '{scan_id}' not found.")
    findings = scan_registry.get_findings(scan_id)
    filtered = filter_findings_collection(
        findings=findings,
        severity=severity,
        confidence_level=confidence_level,
        validation_state=validation_state,
        contextual_priority=contextual_priority,
        correlation_group_id=correlation_group_id,
        include_duplicates=include_duplicates,
    )
    return APIResponse(success=True, data=filtered)


@router.get("/{scan_id}/intelligence", response_model=APIResponse[ScanIntelligenceSummarySchema])
async def get_scan_intelligence(scan_id: UUID) -> APIResponse[ScanIntelligenceSummarySchema]:
    """Retrieves Phase 5 AVIVE intelligence summary and correlation groups for a scan."""
    job = scan_registry.get_job(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Scan job '{scan_id}' not found.")
    summary = scan_registry.get_intelligence_summary(scan_id)
    if not summary:
        return APIResponse(success=True, data=ScanIntelligenceSummarySchema(scan_id=scan_id))
    return APIResponse(success=True, data=summary)


@router.post("/{scan_id}/risk-config", response_model=APIResponse[ScanIntelligenceSummarySchema])
async def update_scan_risk_configuration(
    scan_id: UUID,
    payload: RiskConfigUpdateRequest,
) -> APIResponse[ScanIntelligenceSummarySchema]:
    """Updates analyst-configured asset criticality and recalculates contextual risk priorities."""
    job = scan_registry.get_job(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Scan job '{scan_id}' not found.")
    summary = scan_registry.update_scan_risk_config(scan_id, payload.asset_criticality)
    if not summary:
        raise HTTPException(status_code=404, detail=f"Completed intelligence report for scan '{scan_id}' not found.")
    return APIResponse(
        success=True,
        message=f"Contextual risk recalculated with asset criticality {payload.asset_criticality}.",
        data=summary,
    )


@router.get("/{scan_id}/report")
async def get_scan_report(
    scan_id: UUID,
    format: ReportFormat = Query(ReportFormat.JSON, description="Report output format"),
) -> Response:
    """Retrieves the formatted report for a completed scan job."""
    report = scan_registry.get_report(scan_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report for scan job '{scan_id}' not found or scan not yet completed.")

    try:
        content = report_manager.generate_report(report, format)
        media_type = report_manager.get_content_type(format)
        return Response(content=content, media_type=media_type)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))
