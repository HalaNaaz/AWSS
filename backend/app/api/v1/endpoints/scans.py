from typing import List, Optional
from uuid import UUID, uuid4
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Query, status
from shared.schemas.common import APIResponse, PaginatedResponse, ScanStatus
from shared.schemas.scan import ScanJobCreate, ScanJobResponse

router = APIRouter()

# In-memory registry for foundation / mock testing before full worker deployment
_MOCK_SCANS: dict[UUID, ScanJobResponse] = {}


@router.post("/", response_model=APIResponse[ScanJobResponse], status_code=status.HTTP_201_CREATED)
async def create_scan_job(job_in: ScanJobCreate) -> APIResponse[ScanJobResponse]:
    """Registers and queues a new scan job."""
    scan_id = uuid4()
    job_response = ScanJobResponse(
        id=scan_id,
        target_id=job_in.target_id,
        profile=job_in.profile,
        status=ScanStatus.QUEUED,
        max_crawl_depth=job_in.max_crawl_depth,
        max_urls=job_in.max_urls,
        concurrency=job_in.concurrency,
        rate_limit_rps=job_in.rate_limit_rps,
        created_at=datetime.now(timezone.utc)
    )
    _MOCK_SCANS[scan_id] = job_response
    return APIResponse(
        success=True,
        message="Scan job queued successfully.",
        data=job_response
    )


@router.get("/{scan_id}", response_model=APIResponse[ScanJobResponse])
async def get_scan_status(scan_id: UUID) -> APIResponse[ScanJobResponse]:
    """Retrieves current execution status of a scan job."""
    if scan_id not in _MOCK_SCANS:
        raise HTTPException(status_code=404, detail=f"Scan job '{scan_id}' not found.")
    return APIResponse(success=True, data=_MOCK_SCANS[scan_id])


@router.post("/{scan_id}/cancel", response_model=APIResponse[ScanJobResponse])
async def cancel_scan_job(scan_id: UUID) -> APIResponse[ScanJobResponse]:
    """Cancels an active or queued scan job."""
    if scan_id not in _MOCK_SCANS:
        raise HTTPException(status_code=404, detail=f"Scan job '{scan_id}' not found.")
    job = _MOCK_SCANS[scan_id]
    job.status = ScanStatus.CANCELLED
    return APIResponse(success=True, message="Scan job cancelled.", data=job)
