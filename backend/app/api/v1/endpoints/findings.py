from typing import List, Optional
from uuid import UUID
from fastapi import APIRouter, HTTPException, Query, status
from shared.schemas.common import APIResponse, PaginatedResponse, Severity, FindingStatus
from shared.schemas.finding import FindingResponse

router = APIRouter()

_MOCK_FINDINGS: dict[UUID, FindingResponse] = {}


@router.get("/", response_model=PaginatedResponse[FindingResponse])
async def list_findings(
    scan_id: Optional[UUID] = Query(None, description="Filter findings by scan job ID"),
    severity: Optional[Severity] = Query(None, description="Filter by severity level"),
    status_filter: Optional[FindingStatus] = Query(None, alias="status", description="Filter by finding status"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100)
) -> PaginatedResponse[FindingResponse]:
    """Returns paginated, filterable security vulnerability findings."""
    all_findings = list(_MOCK_FINDINGS.values())
    if scan_id:
        all_findings = [f for f in all_findings if f.scan_id == scan_id]
    if severity:
        all_findings = [f for f in all_findings if f.severity == severity]
    if status_filter:
        all_findings = [f for f in all_findings if f.status == status_filter]

    total = len(all_findings)
    start = (page - 1) * page_size
    items = all_findings[start : start + page_size]
    total_pages = (total + page_size - 1) // page_size if total > 0 else 1

    return PaginatedResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages
    )


@router.get("/{finding_id}", response_model=APIResponse[FindingResponse])
async def get_finding_details(finding_id: UUID) -> APIResponse[FindingResponse]:
    """Retrieves full vulnerability finding details including raw cryptographic evidence."""
    if finding_id not in _MOCK_FINDINGS:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found.")
    return APIResponse(success=True, data=_MOCK_FINDINGS[finding_id])
