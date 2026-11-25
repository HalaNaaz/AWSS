from typing import List, Optional, Any, Dict
from uuid import UUID
from fastapi import APIRouter, HTTPException, Query, status

from backend.app.scanner.orchestration.scan_orchestrator import scan_registry
from backend.app.scanner.discovery.engine import AttackSurfaceIntelligenceEngine
from backend.app.scanner.scope.scope_gate import ScopeGate
from shared.schemas.common import APIResponse
from shared.schemas.discovery import (
    AttackSurfaceSummarySchema,
    AttackSurfaceGraphSchema,
    DiscoveredEndpointCreate,
    ParameterIntelligenceSchema,
    ParameterCategory,
    ParameterLocation,
    APIEndpointSchema,
    APIType,
    AssetIntelligenceSchema,
    AssetType,
    PrioritizedEndpointSchema,
    PriorityLevel,
    EndpointCategory
)

router = APIRouter()


def _get_or_reconstruct_engine(scan_id: UUID) -> AttackSurfaceIntelligenceEngine:
    """Retrieves discovery engine from registry, or reconstructs from report/orchestrator if available."""
    engine = scan_registry.get_discovery_engine(scan_id)
    if engine:
        return engine

    report = scan_registry.get_report(scan_id)
    if report:
        # Reconstruct engine from report data
        gate = ScopeGate(target_base_url=report.target_url, allow_private_ips=True)
        reconstructed = AttackSurfaceIntelligenceEngine(
            target_base_url=report.target_url,
            scope_gate=gate,
            scan_id=scan_id
        )
        for tech in report.technologies:
            reconstructed._add_technology(tech)
        for f in report.findings:
            ep_url = f.endpoint.url if f.endpoint else ""
            reconstructed.record_finding(f.title, ep_url, f.severity.value)
        scan_registry.register_discovery_engine(scan_id, reconstructed)
        return reconstructed

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Attack surface discovery telemetry not found for scan {scan_id}"
    )


@router.get("/{scan_id}/summary", response_model=APIResponse[AttackSurfaceSummarySchema])
def get_attack_surface_summary(scan_id: UUID) -> APIResponse[AttackSurfaceSummarySchema]:
    """Retrieves attack surface discovery summary statistics for a scan."""
    engine = _get_or_reconstruct_engine(scan_id)
    summary = engine.get_summary()
    return APIResponse(
        success=True,
        message="Attack surface discovery summary retrieved successfully",
        data=summary
    )


@router.get("/{scan_id}/endpoints", response_model=APIResponse[List[DiscoveredEndpointCreate]])
def get_discovered_endpoints(
    scan_id: UUID,
    category: Optional[EndpointCategory] = None,
    method: Optional[str] = None,
    min_confidence: Optional[float] = Query(default=0.0, ge=0.0, le=1.0),
    limit: Optional[int] = Query(default=1000, ge=1, le=5000),
    offset: Optional[int] = Query(default=0, ge=0)
) -> APIResponse[List[DiscoveredEndpointCreate]]:
    """Retrieves discovered endpoints with optional filtering and bounded pagination."""
    engine = _get_or_reconstruct_engine(scan_id)
    endpoints = engine.endpoint_engine.get_endpoints()

    if category:
        endpoints = [ep for ep in endpoints if ep.endpoint_category == category]
    if method:
        method_upper = method.upper().strip()
        endpoints = [ep for ep in endpoints if ep.method == method_upper]
    if min_confidence is not None:
        endpoints = [ep for ep in endpoints if ep.confidence >= min_confidence]

    if offset:
        endpoints = endpoints[offset:]
    if limit:
        endpoints = endpoints[:limit]

    return APIResponse(
        success=True,
        message=f"Retrieved {len(endpoints)} discovered endpoints",
        data=endpoints
    )


@router.get("/{scan_id}/parameters", response_model=APIResponse[List[ParameterIntelligenceSchema]])
def get_parameter_intelligence(
    scan_id: UUID,
    category: Optional[ParameterCategory] = None,
    location: Optional[ParameterLocation] = None,
    limit: Optional[int] = Query(default=1000, ge=1, le=5000),
    offset: Optional[int] = Query(default=0, ge=0)
) -> APIResponse[List[ParameterIntelligenceSchema]]:
    """Retrieves discovered parameters with heuristic classification, risk signals, and bounded pagination."""
    engine = _get_or_reconstruct_engine(scan_id)
    parameters = engine.parameter_engine.get_parameters()

    if category:
        parameters = [p for p in parameters if p.category == category]
    if location:
        parameters = [p for p in parameters if p.location == location]

    if offset:
        parameters = parameters[offset:]
    if limit:
        parameters = parameters[:limit]

    return APIResponse(
        success=True,
        message=f"Retrieved {len(parameters)} classified parameters",
        data=parameters
    )


@router.get("/{scan_id}/apis", response_model=APIResponse[List[APIEndpointSchema]])
def get_api_inventory(
    scan_id: UUID,
    api_type: Optional[APIType] = None,
    version: Optional[str] = None,
    limit: Optional[int] = Query(default=1000, ge=1, le=5000),
    offset: Optional[int] = Query(default=0, ge=0)
) -> APIResponse[List[APIEndpointSchema]]:
    """Retrieves API endpoints cataloged by type, version, and bounded pagination."""
    engine = _get_or_reconstruct_engine(scan_id)
    apis = engine.api_engine.get_api_endpoints()

    if api_type:
        apis = [a for a in apis if a.api_type == api_type]
    if version:
        apis = [a for a in apis if a.version == version.lower()]

    if offset:
        apis = apis[offset:]
    if limit:
        apis = apis[:limit]

    return APIResponse(
        success=True,
        message=f"Retrieved {len(apis)} API endpoints",
        data=apis
    )


@router.get("/{scan_id}/assets", response_model=APIResponse[List[AssetIntelligenceSchema]])
def get_asset_inventory(
    scan_id: UUID,
    asset_type: Optional[AssetType] = None,
    limit: Optional[int] = Query(default=1000, ge=1, le=5000),
    offset: Optional[int] = Query(default=0, ge=0)
) -> APIResponse[List[AssetIntelligenceSchema]]:
    """Retrieves client-side assets cataloged during reconnaissance with bounded pagination."""
    engine = _get_or_reconstruct_engine(scan_id)
    assets = engine.asset_engine.get_assets()

    if asset_type:
        assets = [a for a in assets if a.asset_type == asset_type]

    if offset:
        assets = assets[offset:]
    if limit:
        assets = assets[:limit]

    return APIResponse(
        success=True,
        message=f"Retrieved {len(assets)} assets",
        data=assets
    )


@router.get("/{scan_id}/graph")
def get_attack_surface_graph(
    scan_id: UUID,
    graph_format: str = Query(default="json", pattern="^(json|cytoscape)$")
) -> Any:
    """Retrieves the attack surface graph in standard JSON or Cytoscape.js format."""
    engine = _get_or_reconstruct_engine(scan_id)

    if graph_format == "cytoscape":
        cyto_data = engine.graph.to_cytoscape()
        return APIResponse(
            success=True,
            message="Cytoscape graph elements retrieved successfully",
            data=cyto_data
        )

    graph_schema = engine.graph.to_schema()
    return APIResponse(
        success=True,
        message="Attack surface graph retrieved successfully",
        data=graph_schema
    )


@router.get("/{scan_id}/prioritized", response_model=APIResponse[List[PrioritizedEndpointSchema]])
def get_prioritized_endpoints(
    scan_id: UUID,
    priority_level: Optional[PriorityLevel] = None,
    limit: Optional[int] = Query(default=1000, ge=1, le=5000),
    offset: Optional[int] = Query(default=0, ge=0)
) -> APIResponse[List[PrioritizedEndpointSchema]]:
    """Retrieves evidence-prioritized endpoints ranked by exploration value with bounded pagination."""
    engine = _get_or_reconstruct_engine(scan_id)
    prioritized = engine.get_prioritized_endpoints()

    if priority_level:
        prioritized = [p for p in prioritized if p.priority_level == priority_level]

    if offset:
        prioritized = prioritized[offset:]
    if limit:
        prioritized = prioritized[:limit]

    return APIResponse(
        success=True,
        message=f"Retrieved {len(prioritized)} prioritized endpoints",
        data=prioritized
    )
