from typing import List, Dict, Optional
from uuid import UUID, uuid4
from fastapi import APIRouter, HTTPException, Query, status

from shared.schemas.common import APIResponse, PaginatedResponse
from shared.schemas.discovery import (
    ReconStartRequest,
    ReconSummaryResponse,
    DiscoveredEndpointResponse,
    TechnologyObservationSchema
)

router = APIRouter()

# In-memory store for active recon sessions in foundation/API testing
_RECON_SESSIONS: Dict[UUID, ReconSummaryResponse] = {}
_DISCOVERED_ENDPOINTS_STORE: Dict[UUID, List[DiscoveredEndpointResponse]] = {}


@router.post("/start", response_model=APIResponse[ReconSummaryResponse], status_code=status.HTTP_201_CREATED)
async def start_recon_job(req: ReconStartRequest) -> APIResponse[ReconSummaryResponse]:
    """Initiates an authorized reconnaissance and crawling job against a registered target."""
    scan_id = uuid4()
    
    # Initialize session summary
    summary = ReconSummaryResponse(
        scan_id=scan_id,
        target_url="https://target.local",
        status="QUEUED",
        urls_crawled=0,
        endpoints_discovered=0,
        forms_discovered=0,
        technologies_detected=0,
        crawl_depth_reached=0,
        execution_time_seconds=0.0,
        categories_breakdown={},
        technologies=[]
    )
    _RECON_SESSIONS[scan_id] = summary
    _DISCOVERED_ENDPOINTS_STORE[scan_id] = []

    return APIResponse(
        success=True,
        message="Reconnaissance job initialized successfully.",
        data=summary
    )


@router.get("/{scan_id}/status", response_model=APIResponse[ReconSummaryResponse])
async def get_recon_status(scan_id: UUID) -> APIResponse[ReconSummaryResponse]:
    """Retrieves execution summary and metrics for a reconnaissance session."""
    if scan_id not in _RECON_SESSIONS:
        raise HTTPException(status_code=404, detail=f"Recon session '{scan_id}' not found.")
    return APIResponse(success=True, data=_RECON_SESSIONS[scan_id])


@router.get("/{scan_id}/endpoints", response_model=PaginatedResponse[DiscoveredEndpointResponse])
async def list_discovered_endpoints(
    scan_id: UUID,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100)
) -> PaginatedResponse[DiscoveredEndpointResponse]:
    """Retrieves paginated discovered endpoints for a scan job."""
    endpoints = _DISCOVERED_ENDPOINTS_STORE.get(scan_id, [])
    total = len(endpoints)
    start = (page - 1) * page_size
    items = endpoints[start : start + page_size]
    total_pages = (total + page_size - 1) // page_size if total > 0 else 1

    return PaginatedResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages
    )


@router.get("/{scan_id}/technologies", response_model=APIResponse[List[TechnologyObservationSchema]])
async def list_technologies(scan_id: UUID) -> APIResponse[List[TechnologyObservationSchema]]:
    """Retrieves detected technologies and frameworks for a scan job."""
    if scan_id not in _RECON_SESSIONS:
        raise HTTPException(status_code=404, detail=f"Recon session '{scan_id}' not found.")
    return APIResponse(success=True, data=_RECON_SESSIONS[scan_id].technologies)


@router.post("/{scan_id}/cancel", response_model=APIResponse[ReconSummaryResponse])
async def cancel_recon_job(scan_id: UUID) -> APIResponse[ReconSummaryResponse]:
    """Cancels an active reconnaissance session."""
    if scan_id not in _RECON_SESSIONS:
        raise HTTPException(status_code=404, detail=f"Recon session '{scan_id}' not found.")
    session = _RECON_SESSIONS[scan_id]
    session.status = "CANCELLED"
    return APIResponse(success=True, message="Reconnaissance job cancelled.", data=session)
