from typing import List, Dict, Any, Optional
from uuid import UUID, uuid4
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from backend.app.scanner.passive.engine import PassiveAnalysisEngine
from backend.app.scanner.passive.models import HTTPResponseContext, PassiveFinding
from backend.app.api.v1.endpoints.findings import _MOCK_FINDINGS
from shared.schemas.common import APIResponse, PaginatedResponse
from shared.schemas.finding import FindingResponse

router = APIRouter()
_engine = PassiveAnalysisEngine()


class PassiveAnalyzeRequest(BaseModel):
    url: str
    status_code: int = 200
    headers: Dict[str, str] = Field(default_factory=dict)
    body: Optional[str] = Field(None, max_length=5_000_000, description="Response body up to 5MB")
    method: str = "GET"
    scan_id: Optional[UUID] = None


class PassiveAnalyzerMetadata(BaseModel):
    analyzer_id: str
    name: str
    category: str
    supported_rules_count: int
    supported_rules: List[str]


@router.get("/analyzers", response_model=APIResponse[List[PassiveAnalyzerMetadata]])
async def list_passive_analyzers() -> APIResponse[List[PassiveAnalyzerMetadata]]:
    """Lists all active passive security check analyzers and their rule capabilities."""
    analyzers = _engine.list_analyzers()
    return APIResponse(
        success=True,
        message=f"Retrieved {len(analyzers)} registered passive analyzers.",
        data=[PassiveAnalyzerMetadata(**a) for a in analyzers]
    )


@router.get("/rules", response_model=APIResponse[List[str]])
async def list_passive_rules() -> APIResponse[List[str]]:
    """Lists all supported passive rule identifiers across all analyzers."""
    rules = _engine.list_all_rules()
    return APIResponse(
        success=True,
        message=f"Retrieved {len(rules)} supported passive security rules.",
        data=rules
    )


@router.post("/analyze", response_model=APIResponse[List[FindingResponse]], status_code=status.HTTP_200_OK)
async def analyze_http_response(req: PassiveAnalyzeRequest) -> APIResponse[List[FindingResponse]]:
    """Analyzes an HTTP request/response transaction passively without generating external network traffic."""
    scan_id = req.scan_id or uuid4()
    ctx = HTTPResponseContext(
        url=req.url,
        status_code=req.status_code,
        headers=req.headers,
        raw_headers=[(k, v) for k, v in req.headers.items()],
        body=req.body,
        method=req.method
    )

    findings = _engine.analyze_response(ctx)
    converted: List[FindingResponse] = []
    for f in findings:
        resp = f.to_finding_response(scan_id)
        converted.append(resp)
        # Store in global findings store for retrieval via /findings
        _MOCK_FINDINGS[resp.id] = resp

    return APIResponse(
        success=True,
        message=f"Passive analysis completed. Generated {len(converted)} security findings.",
        data=converted
    )


@router.get("/{scan_id}/findings", response_model=PaginatedResponse[FindingResponse])
async def get_passive_findings_by_scan(
    scan_id: UUID,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100)
) -> PaginatedResponse[FindingResponse]:
    """Retrieves paginated passive findings associated with a scan ID."""
    findings_for_scan = [f for f in _MOCK_FINDINGS.values() if f.scan_id == scan_id]
    total = len(findings_for_scan)
    start = (page - 1) * page_size
    items = findings_for_scan[start : start + page_size]
    total_pages = (total + page_size - 1) // page_size if total > 0 else 1

    return PaginatedResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages
    )
