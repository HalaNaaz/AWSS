from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID
from fastapi import APIRouter, HTTPException, Query, status

from backend.app.scanner.intelligence.validation import SafeValidationWorkflow
from backend.app.scanner.orchestration.scan_orchestrator import scan_registry
from shared.schemas.common import APIResponse, FindingStatus, PaginatedResponse, Severity
from shared.schemas.finding import FindingResponse
from shared.schemas.intelligence import (
    ConfidenceLevel,
    ContextualPriority,
    RemediationPriority,
    RemediationStatus,
    RemediationStatusUpdateRequest,
    ValidationState,
    ValidationTransitionRequest,
)

router = APIRouter()


def filter_findings_collection(
    findings: List[FindingResponse],
    scan_id: Optional[UUID] = None,
    target_id: Optional[UUID] = None,
    severity: Optional[Severity] = None,
    status_filter: Optional[FindingStatus] = None,
    confidence_level: Optional[ConfidenceLevel] = None,
    validation_state: Optional[ValidationState] = None,
    cwe_id: Optional[str] = None,
    category: Optional[str] = None,
    asset: Optional[str] = None,
    correlation_group_id: Optional[str] = None,
    contextual_priority: Optional[ContextualPriority] = None,
    remediation_priority: Optional[RemediationPriority] = None,
    remediation_status: Optional[RemediationStatus] = None,
    include_duplicates: bool = True,
    search: Optional[str] = None,
) -> List[FindingResponse]:
    """Applies multi-dimensional AVIVE filters to a finding collection."""
    results = list(findings)

    if scan_id:
        results = [f for f in results if f.scan_id == scan_id]
    if target_id:
        results = [
            f for f in results
            if f.target_id == target_id or (f.intelligence and f.intelligence.target_id == target_id)
        ]
    if severity:
        results = [f for f in results if f.severity == severity]
    if status_filter:
        results = [f for f in results if f.status == status_filter]
    if not include_duplicates:
        results = [f for f in results if not (f.intelligence and f.intelligence.is_duplicate)]
    if confidence_level:
        results = [
            f for f in results
            if f.intelligence and f.intelligence.confidence_assessment.level == confidence_level
        ]
    if validation_state:
        results = [
            f for f in results
            if f.intelligence and f.intelligence.validation_state == validation_state
        ]
    if cwe_id:
        norm_cwe = cwe_id.strip().upper()
        results = [f for f in results if f.cwe_id.upper() == norm_cwe]
    if category:
        norm_cat = category.strip().upper()
        results = [
            f for f in results
            if f.intelligence and f.intelligence.vulnerability_category.upper() == norm_cat
        ]
    if asset:
        asset_q = asset.strip().lower()
        results = [
            f for f in results
            if (f.intelligence and any(asset_q in a.lower() for a in f.intelligence.asset_relationships))
            or (f.endpoint and asset_q in f.endpoint.url.lower())
        ]
    if correlation_group_id:
        results = [
            f for f in results
            if f.intelligence and f.intelligence.correlation_group_id == correlation_group_id
        ]
    if contextual_priority:
        results = [
            f for f in results
            if f.intelligence and f.intelligence.contextual_risk.contextual_priority == contextual_priority
        ]
    if remediation_priority:
        results = [
            f for f in results
            if f.intelligence and f.intelligence.remediation_intelligence.remediation_priority == remediation_priority
        ]
    if remediation_status:
        results = [
            f for f in results
            if f.intelligence and f.intelligence.remediation_intelligence.remediation_status == remediation_status
        ]
    if search:
        q = search.strip().lower()
        results = [
            f for f in results
            if q in f.title.lower()
            or q in f.cwe_id.lower()
            or (f.endpoint and q in f.endpoint.url.lower())
            or (f.endpoint and f.endpoint.parameter and q in f.endpoint.parameter.lower())
        ]

    return results


@router.get("/", response_model=PaginatedResponse[FindingResponse])
async def list_findings(
    scan_id: Optional[UUID] = Query(None, description="Filter findings by scan job ID"),
    target_id: Optional[UUID] = Query(None, description="Filter findings by target ID"),
    severity: Optional[Severity] = Query(None, description="Filter by severity level"),
    status_filter: Optional[FindingStatus] = Query(None, alias="status", description="Filter by finding status"),
    confidence_level: Optional[ConfidenceLevel] = Query(None, description="Filter by AVIVE confidence classification"),
    validation_state: Optional[ValidationState] = Query(None, description="Filter by AVIVE validation state"),
    cwe_id: Optional[str] = Query(None, max_length=32, description="Filter by CWE ID (e.g. CWE-79)"),
    category: Optional[str] = Query(None, max_length=64, description="Filter by vulnerability category"),
    asset: Optional[str] = Query(None, max_length=255, description="Filter by host/asset identifier"),
    correlation_group_id: Optional[str] = Query(None, max_length=64, description="Filter by correlation group ID"),
    contextual_priority: Optional[ContextualPriority] = Query(None, description="Filter by contextual priority"),
    remediation_priority: Optional[RemediationPriority] = Query(None, description="Filter by remediation priority"),
    remediation_status: Optional[RemediationStatus] = Query(None, description="Filter by remediation tracking status"),
    include_duplicates: bool = Query(True, description="Include findings flagged as duplicates in correlation groups"),
    search: Optional[str] = Query(None, max_length=200, description="Search title, CWE, endpoint, or parameter"),
    page: int = Query(1, ge=1, le=10000),
    page_size: int = Query(20, ge=1, le=100),
) -> PaginatedResponse[FindingResponse]:
    """Returns paginated, filterable vulnerability findings enriched with AVIVE intelligence."""
    all_findings = scan_registry.get_findings(scan_id) if scan_id else scan_registry.get_all_findings()
    filtered = filter_findings_collection(
        findings=all_findings,
        scan_id=scan_id,
        target_id=target_id,
        severity=severity,
        status_filter=status_filter,
        confidence_level=confidence_level,
        validation_state=validation_state,
        cwe_id=cwe_id,
        category=category,
        asset=asset,
        correlation_group_id=correlation_group_id,
        contextual_priority=contextual_priority,
        remediation_priority=remediation_priority,
        remediation_status=remediation_status,
        include_duplicates=include_duplicates,
        search=search,
    )

    total = len(filtered)
    start = (page - 1) * page_size
    items = filtered[start : start + page_size]
    total_pages = (total + page_size - 1) // page_size if total > 0 else 1

    return PaginatedResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


def _resolve_finding_with_ownership(
    finding_id: UUID,
    expected_scan_id: Optional[UUID] = None,
    expected_target_id: Optional[UUID] = None,
) -> tuple[FindingResponse, Optional[Any]]:
    match = scan_registry.get_finding_by_id(finding_id)
    if not match:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Finding '{finding_id}' not found.")

    finding, report = match
    if expected_scan_id and finding.scan_id != expected_scan_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cross-scan access denied: Finding does not belong to specified scan_id.",
        )
    if expected_target_id:
        actual_target = finding.target_id or (finding.intelligence.target_id if finding.intelligence else None)
        if actual_target != expected_target_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cross-target isolation violation: Finding does not belong to specified target_id.",
            )
    return (finding, report)


@router.get("/{finding_id}", response_model=APIResponse[FindingResponse])
async def get_finding_details(
    finding_id: UUID,
    scan_id: Optional[UUID] = Query(None, description="Optional owning scan_id for isolation verification"),
    target_id: Optional[UUID] = Query(None, description="Optional owning target_id for isolation verification"),
) -> APIResponse[FindingResponse]:
    """Retrieves full vulnerability finding details including AVIVE intelligence and SHA-256 evidence."""
    finding, _ = _resolve_finding_with_ownership(finding_id, scan_id, target_id)
    return APIResponse(success=True, data=finding)


@router.get("/{finding_id}/relationships", response_model=APIResponse[Dict[str, Any]])
async def get_finding_relationships(
    finding_id: UUID,
    scan_id: Optional[UUID] = Query(None),
    target_id: Optional[UUID] = Query(None),
) -> APIResponse[Dict[str, Any]]:
    """Retrieves correlation group, related findings, asset, and technology relationships for a finding."""
    finding, report = _resolve_finding_with_ownership(finding_id, scan_id, target_id)
    if not finding.intelligence:
        return APIResponse(
            success=True,
            data={
                "finding_id": str(finding.id),
                "correlation_group": None,
                "related_findings": [],
                "asset_relationships": [],
                "technology_relationships": [],
            },
        )

    intel = finding.intelligence
    group = None
    if report and report.intelligence_summary and intel.correlation_group_id:
        for grp in report.intelligence_summary.correlation_groups:
            if grp.group_id == intel.correlation_group_id:
                group = grp
                break

    related_summaries = []
    if report and intel.related_finding_ids:
        related_set = set(intel.related_finding_ids)
        for cand in report.findings:
            if cand.id in related_set:
                related_summaries.append({
                    "id": str(cand.id),
                    "title": cand.title,
                    "cwe_id": cand.cwe_id,
                    "severity": cand.severity.value,
                    "endpoint": cand.endpoint.url,
                    "parameter": cand.endpoint.parameter,
                    "validation_state": cand.intelligence.validation_state.value if cand.intelligence else cand.status.value,
                })

    return APIResponse(
        success=True,
        data={
            "finding_id": str(finding.id),
            "fingerprint": intel.fingerprint,
            "is_primary": intel.is_primary,
            "is_duplicate": intel.is_duplicate,
            "duplicate_of": str(intel.duplicate_of) if intel.duplicate_of else None,
            "correlation_relationship": intel.correlation_relationship.value,
            "correlation_confidence": intel.correlation_confidence,
            "correlation_explanation": intel.correlation_explanation,
            "correlation_group": group.model_dump(mode="json") if group else None,
            "related_findings": related_summaries,
            "asset_relationships": intel.asset_relationships,
            "technology_relationships": intel.technology_relationships,
        },
    )


@router.post("/{finding_id}/validate", response_model=APIResponse[FindingResponse])
async def validate_finding_state(
    finding_id: UUID,
    payload: ValidationTransitionRequest,
) -> APIResponse[FindingResponse]:
    """Executes an audited validation state transition or bounded ScopeGate-enforced safe re-validation."""
    finding, report = _resolve_finding_with_ownership(
        finding_id,
        expected_scan_id=payload.scan_id,
        expected_target_id=payload.target_id,
    )
    if not finding.intelligence:
        raise HTTPException(status_code=400, detail="Finding lacks AVIVE intelligence state machine.")

    if payload.run_safe_revalidation:
        if not payload.authorized:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Safety Gate Violation: Explicit authorization confirmation ('authorized=true') is required for live re-validation probes.",
            )
        target_base_url = report.target_url if report else finding.endpoint.url
        try:
            updated, passed, msg = await SafeValidationWorkflow.run_safe_revalidation(
                finding=finding,
                target_base_url=target_base_url,
                authorized=payload.authorized,
                actor=payload.actor,
            )
            return APIResponse(success=True, message=msg, data=updated)
        except PermissionError as p_err:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(p_err))
        except ValueError as v_err:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(v_err))

    # Analyst-driven controlled transition
    try:
        updated = SafeValidationWorkflow.transition(
            finding=finding,
            target_state=payload.target_state,
            actor=payload.actor,
            validation_method=payload.validation_method,
            supporting_evidence=payload.supporting_evidence,
            notes=payload.notes,
        )
        return APIResponse(
            success=True,
            message=f"Validation state transitioned to {payload.target_state.value}.",
            data=updated,
        )
    except ValueError as v_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(v_err))


@router.post("/{finding_id}/remediation", response_model=APIResponse[FindingResponse])
async def update_finding_remediation_status(
    finding_id: UUID,
    payload: RemediationStatusUpdateRequest,
    scan_id: Optional[UUID] = Query(None),
    target_id: Optional[UUID] = Query(None),
) -> APIResponse[FindingResponse]:
    """Updates remediation tracking status for a finding."""
    finding, _ = _resolve_finding_with_ownership(finding_id, scan_id, target_id)
    if not finding.intelligence:
        raise HTTPException(status_code=400, detail="Finding lacks AVIVE remediation intelligence.")

    finding.intelligence.remediation_intelligence.remediation_status = payload.remediation_status
    finding.updated_at = datetime.now(timezone.utc)

    # Optionally advance validation state to RESOLVED when verified fixed
    if payload.remediation_status == RemediationStatus.VERIFIED_FIXED:
        try:
            SafeValidationWorkflow.transition(
                finding=finding,
                target_state=ValidationState.RESOLVED,
                actor=payload.actor,
                validation_method="remediation_verification",
                notes=payload.notes or "Marked verified fixed.",
            )
        except ValueError:
            pass

    return APIResponse(
        success=True,
        message=f"Remediation status updated to {payload.remediation_status.value}.",
        data=finding,
    )
