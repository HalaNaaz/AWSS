from typing import List, Dict, Any, Optional
from uuid import UUID, uuid4
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from backend.app.core.exceptions import ScopeViolationError, SSRFValidationError
from backend.app.core.logging import logger
from backend.app.scanner.active.registry import active_plugin_registry
from backend.app.scanner.active.engine import ActiveDetectionEngine
from backend.app.scanner.active.models import ActiveTarget
from backend.app.scanner.scope.scope_gate import ScopeGate
from backend.app.scanner.crawler.client import AsyncHTTPClient
from shared.schemas.common import APIResponse, ScanProfile
from shared.schemas.finding import FindingResponse

router = APIRouter()

ALLOWED_PROBE_METHODS = {"GET", "POST", "HEAD", "OPTIONS", "PUT"}


class ActiveAnalyzerMetadata(BaseModel):
    analyzer_id: str
    name: str
    category: str
    safe_mode_compatible: bool
    supported_rules_count: int
    supported_rules: List[str]


class ActiveProbeRequest(BaseModel):
    url: str
    method: str = "GET"
    parameters: Dict[str, str] = Field(default_factory=dict)
    profile: ScanProfile = ScanProfile.SAFE_ACTIVE
    modules: Optional[List[str]] = None
    target_id: Optional[UUID] = None
    authorized: bool = Field(False, description="Mandatory authorization confirmation (Safety Gate)")
    request_budget: int = Field(default=20, ge=1, le=100)


@router.get("/analyzers", response_model=APIResponse[List[ActiveAnalyzerMetadata]])
async def list_active_analyzers() -> APIResponse[List[ActiveAnalyzerMetadata]]:
    """Lists all registered active vulnerability detection analyzers and their capabilities."""
    analyzers = active_plugin_registry.list_analyzers()
    return APIResponse(
        success=True,
        message=f"Retrieved {len(analyzers)} registered active analyzers.",
        data=[ActiveAnalyzerMetadata(**a) for a in analyzers],
    )


@router.get("/rules", response_model=APIResponse[List[str]])
async def list_active_rules() -> APIResponse[List[str]]:
    """Lists all supported active security detection rules across all modules."""
    rules = active_plugin_registry.list_all_rules()
    return APIResponse(
        success=True,
        message=f"Retrieved {len(rules)} supported active security rules.",
        data=rules,
    )


@router.post("/probe", response_model=APIResponse[List[FindingResponse]])
async def probe_endpoint_actively(request_in: ActiveProbeRequest) -> APIResponse[List[FindingResponse]]:
    """Executes controlled, authorized active vulnerability checks against a specific endpoint."""
    if not request_in.authorized:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Safety Gate Violation: Explicit authorization confirmation ('authorized: true') is mandatory before conducting active security testing.",
        )

    probe_method = request_in.method.upper()
    if probe_method not in ALLOWED_PROBE_METHODS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported HTTP probe method '{request_in.method}'. Supported methods: {', '.join(sorted(ALLOWED_PROBE_METHODS))}",
        )

    scan_id = uuid4()
    scope_gate = ScopeGate(target_base_url=request_in.url, allow_private_ips=False)

    # Validate target URL via ScopeGate
    if not scope_gate.validate_url_in_scope(request_in.url):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Target URL '{request_in.url}' violates ScopeGate restrictions.",
        )

    try:
        scope_gate.pre_flight_check(request_in.url)
    except (ScopeViolationError, SSRFValidationError) as sec_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Safety Gate rejected target: {sec_err.message}",
        )
    except Exception as e:
        logger.debug(f"Pre-flight resolution in probe endpoint: {e}")

    target = ActiveTarget(
        url=request_in.url,
        method=probe_method,
        parameters=request_in.parameters,
    )

    budget_val = min(max(1, request_in.request_budget), 100)
    engine = ActiveDetectionEngine(
        registry=active_plugin_registry,
        request_budget=budget_val,
        concurrency=2,
        timeout_seconds=10.0,
    )

    enabled_modules_set = set(request_in.modules) if request_in.modules else None

    async with AsyncHTTPClient(scope_gate=scope_gate, rate_limit_rps=5.0) as client:
        active_findings = await engine.run(
            targets=[target],
            client=client,
            scan_id=scan_id,
            profile=request_in.profile,
            enabled_modules=enabled_modules_set,
        )

    findings_response = [af.to_finding_response(scan_id) for af in active_findings]
    return APIResponse(
        success=True,
        message=f"Active testing completed. Identified {len(findings_response)} findings.",
        data=findings_response,
    )
