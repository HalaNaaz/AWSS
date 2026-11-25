from typing import Dict, List, Optional, Any, Set
from urllib.parse import urlparse
from uuid import UUID

from backend.app.scanner.discovery.endpoint_discovery import AdvancedEndpointDiscovery
from backend.app.scanner.discovery.js_analyzer import JSStaticIntelligenceAnalyzer, JSAnalysisResult
from backend.app.scanner.discovery.parameter_intelligence import ParameterIntelligenceEngine
from backend.app.scanner.discovery.api_discovery import APIDiscoveryEngine
from backend.app.scanner.discovery.asset_inventory import AssetInventoryManager
from backend.app.scanner.discovery.technology_fingerprinter import AdvancedTechnologyFingerprinter
from backend.app.scanner.discovery.attack_surface_graph import AttackSurfaceGraph
from backend.app.scanner.discovery.prioritizer import DiscoveryPrioritizationEngine
from backend.app.scanner.scope.scope_gate import ScopeGate
from shared.schemas.discovery import (
    DiscoveredEndpointCreate,
    ParameterIntelligenceSchema,
    ParameterLocation,
    APIEndpointSchema,
    AssetIntelligenceSchema,
    TechnologyObservationSchema,
    AttackSurfaceGraphSchema,
    PrioritizedEndpointSchema,
    AttackSurfaceSummarySchema,
    NodeType,
    EdgeType,
    DiscoveryMethod,
    EndpointCategory
)


class AttackSurfaceIntelligenceEngine:
    """Master Orchestrator for Phase 4: Advanced Attack Surface Discovery & Intelligence.
    
    Coordinates the 8 discovery subsystems:
    1. Advanced Endpoint Discovery (Module 4.1)
    2. JavaScript Static Intelligence (Module 4.2)
    3. Parameter Intelligence (Module 4.3)
    4. API Discovery & Surface Inventory (Module 4.4)
    5. Asset Intelligence (Module 4.5)
    6. Advanced Technology Fingerprinting (Module 4.6)
    7. Attack Surface Graph (Module 4.7)
    8. Discovery Prioritization (Module 4.8)
    """

    def __init__(self, target_base_url: str, scope_gate: ScopeGate, scan_id: UUID):
        self.target_base_url = target_base_url
        self.scope_gate = scope_gate
        self.scan_id = scan_id

        # Subsystem engines
        self.endpoint_engine = AdvancedEndpointDiscovery(target_base_url, scope_gate, scan_id)
        self.parameter_engine = ParameterIntelligenceEngine()
        self.api_engine = APIDiscoveryEngine()
        self.asset_engine = AssetInventoryManager()
        self.graph = AttackSurfaceGraph(scan_id)

        # Observations and findings
        self.technologies: List[TechnologyObservationSchema] = []
        self.findings_by_url: Dict[str, int] = {}
        self.forms_by_action: Dict[str, bool] = {}

        # Add Root Target Domain Node in Graph
        parsed_target = urlparse(target_base_url)
        domain = parsed_target.netloc or target_base_url
        self.domain_node_id = f"domain:{domain}"
        self.graph.add_node(
            node_id=self.domain_node_id,
            label=domain,
            node_type=NodeType.DOMAIN,
            metadata={"base_url": target_base_url, "scheme": parsed_target.scheme}
        )

    def ingest_crawled_page(
        self,
        url: str,
        status_code: Optional[int] = None,
        content_type: Optional[str] = None,
        response_size: Optional[int] = None,
        response_time_ms: Optional[float] = None,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        source_url: Optional[str] = None,
        crawl_depth: int = 0
    ) -> Optional[DiscoveredEndpointCreate]:
        """Ingests a crawled HTTP transaction, feeding it through discovery analyzers."""
        # 1. Endpoint Discovery
        ep = self.endpoint_engine.add_endpoint(
            raw_url=url,
            method="GET",
            discovery_method=DiscoveryMethod.CRAWLER,
            source_url=source_url,
            status_code=status_code,
            content_type=content_type,
            response_size=response_size,
            response_time_ms=response_time_ms,
            crawl_depth=crawl_depth
        )

        if not ep:
            return None

        norm_url = ep.normalized_url

        # Add Endpoint Node to Graph
        ep_node_id = f"ep:{norm_url}:GET"
        self.graph.add_node(
            node_id=ep_node_id,
            label=f"GET {norm_url}",
            node_type=NodeType.ENDPOINT,
            metadata={"category": ep.endpoint_category.value, "status_code": status_code}
        )
        self.graph.add_edge(
            source_id=self.domain_node_id,
            target_id=ep_node_id,
            edge_type=EdgeType.HOSTED_ON
        )

        if source_url:
            src_node_id = f"ep:{source_url}:GET"
            if src_node_id in self.graph._nodes:
                self.graph.add_edge(
                    source_id=src_node_id,
                    target_id=ep_node_id,
                    edge_type=EdgeType.LINKS_TO
                )

        # 2. Extract Query Parameters
        url_params = self.parameter_engine.extract_from_url(norm_url)
        for param in url_params:
            p_node_id = f"param:{param.name}:{param.location.value}"
            self.graph.add_node(
                node_id=p_node_id,
                label=f"{param.name} ({param.category.value})",
                node_type=NodeType.PARAMETER,
                metadata={"category": param.category.value, "location": param.location.value}
            )
            self.graph.add_edge(
                source_id=ep_node_id,
                target_id=p_node_id,
                edge_type=EdgeType.HAS_PARAMETER
            )

        # 3. API Discovery
        api_ep = self.api_engine.record_api_endpoint(
            url=norm_url,
            method="GET",
            content_type=content_type,
            status_code=status_code,
            parameters=[p.name for p in url_params],
            discovery_source="CRAWLER"
        )
        if api_ep:
            api_node_id = f"api:{norm_url}"
            self.graph.add_node(
                node_id=api_node_id,
                label=f"API: {norm_url}",
                node_type=NodeType.API_ROUTE,
                metadata={"api_type": api_ep.api_type.value, "version": api_ep.version}
            )
            self.graph.add_edge(
                source_id=ep_node_id,
                target_id=api_node_id,
                edge_type=EdgeType.ASSOCIATED_WITH
            )

        # 4. Asset Inventory
        if ep.endpoint_category in (EndpointCategory.JAVASCRIPT, EndpointCategory.CSS, EndpointCategory.IMAGE, EndpointCategory.DOCUMENT):
            asset = self.asset_engine.record_asset(
                url=norm_url,
                content_type=content_type,
                size_bytes=response_size,
                discovery_source="CRAWLER",
                in_scope=True,
                associated_endpoint=source_url
            )
            if asset:
                asset_node_id = f"asset:{norm_url}"
                self.graph.add_node(
                    node_id=asset_node_id,
                    label=f"Asset: {norm_url}",
                    node_type=NodeType.JS_ASSET if asset.asset_type.value == "JAVASCRIPT" else NodeType.URL,
                    metadata={"asset_type": asset.asset_type.value}
                )
                self.graph.add_edge(
                    source_id=ep_node_id,
                    target_id=asset_node_id,
                    edge_type=EdgeType.USES_ASSET
                )

        # 5. Technology Fingerprinting (if headers / body present)
        if headers:
            detected_techs = AdvancedTechnologyFingerprinter.fingerprint(
                scan_id=self.scan_id,
                headers=headers,
                html_body=body
            )
            for tech in detected_techs:
                self._add_technology(tech)

        return ep

    def ingest_form(self, action_url: str, method: str, fields: List[Dict[str, Any]], source_url: Optional[str] = None):
        """Ingests an HTML form definition."""
        norm_action = self.endpoint_engine.add_endpoint(
            raw_url=action_url,
            method=method,
            discovery_method=DiscoveryMethod.FORM_ACTION,
            source_url=source_url
        )
        action_target = norm_action.normalized_url if norm_action else action_url
        self.forms_by_action[action_target] = True

        form_node_id = f"form:{action_target}:{method.upper()}"
        self.graph.add_node(
            node_id=form_node_id,
            label=f"Form -> {method.upper()} {action_target}",
            node_type=NodeType.FORM,
            metadata={"fields_count": len(fields)}
        )
        if source_url:
            src_node_id = f"ep:{source_url}:GET"
            if src_node_id in self.graph._nodes:
                self.graph.add_edge(
                    source_id=src_node_id,
                    target_id=form_node_id,
                    edge_type=EdgeType.LINKS_TO
                )

        # Extract Form Parameters
        form_params = self.parameter_engine.extract_from_form_fields(fields, action_target)
        for param in form_params:
            p_node_id = f"param:{param.name}:{param.location.value}"
            self.graph.add_node(
                node_id=p_node_id,
                label=f"{param.name} ({param.category.value})",
                node_type=NodeType.PARAMETER,
                metadata={"category": param.category.value, "location": param.location.value}
            )
            self.graph.add_edge(
                source_id=form_node_id,
                target_id=p_node_id,
                edge_type=EdgeType.HAS_PARAMETER
            )

    def ingest_javascript(self, js_content: str, js_url: str) -> JSAnalysisResult:
        """Statically analyzes JavaScript content without dynamic execution."""
        result = JSStaticIntelligenceAnalyzer.analyze_js(
            js_content=js_content,
            base_url=self.target_base_url,
            scope_gate=self.scope_gate
        )

        js_node_id = f"asset:{js_url}"
        self.graph.add_node(
            node_id=js_node_id,
            label=f"JS: {js_url}",
            node_type=NodeType.JS_ASSET
        )

        # Ingest discovered endpoints
        for ep_url in result.endpoints:
            ep = self.endpoint_engine.add_endpoint(
                raw_url=ep_url,
                method="GET",
                discovery_method=DiscoveryMethod.STATIC_JS_ANALYSIS,
                source_url=js_url,
                confidence=0.80
            )
            if ep:
                ep_node_id = f"ep:{ep.normalized_url}:GET"
                self.graph.add_node(
                    node_id=ep_node_id,
                    label=f"GET {ep.normalized_url}",
                    node_type=NodeType.ENDPOINT
                )
                self.graph.add_edge(
                    source_id=js_node_id,
                    target_id=ep_node_id,
                    edge_type=EdgeType.REFERENCES
                )

        # Ingest API routes
        for api_url in result.api_routes:
            self.api_engine.record_api_endpoint(
                url=api_url,
                method="GET",
                discovery_source="STATIC_JS_ANALYSIS",
                confidence=0.85
            )

        # Ingest parameters discovered in JS
        for p_name in result.parameter_names:
            self.parameter_engine.record_parameter(
                name=p_name,
                location=ParameterLocation.QUERY,
                endpoint_url=js_url
            )

        # Ingest Source Maps as Assets
        for sm_url in result.sourcemap_urls:
            self.asset_engine.record_asset(
                url=sm_url,
                content_type="application/json",
                discovery_source="STATIC_JS_ANALYSIS",
                associated_endpoint=js_url
            )

        return result

    def record_finding(self, finding_title: str, endpoint_url: str, severity: str):
        """Attaches a finding to an endpoint for attack surface correlation."""
        self.findings_by_url[endpoint_url] = self.findings_by_url.get(endpoint_url, 0) + 1

        f_node_id = f"finding:{endpoint_url}:{finding_title}"
        self.graph.add_node(
            node_id=f_node_id,
            label=f"[{severity}] {finding_title}",
            node_type=NodeType.FINDING,
            metadata={"severity": severity}
        )
        # Link to matching endpoint node if present in graph (support GET, POST, or other methods)
        for method in ("GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE"):
            ep_node_id = f"ep:{endpoint_url}:{method}"
            if ep_node_id in self.graph._nodes:
                self.graph.add_edge(
                    source_id=ep_node_id,
                    target_id=f_node_id,
                    edge_type=EdgeType.HAS_FINDING
                )
                break

    def _add_technology(self, tech: TechnologyObservationSchema):
        """Registers a technology observation and links it to domain in graph."""
        # Check if already present
        for t in self.technologies:
            if t.technology_name == tech.technology_name:
                t.indicators_count += 1
                t.confidence = min(0.99, max(t.confidence, tech.confidence))
                if tech.version and not t.version:
                    t.version = tech.version
                if tech.is_confirmed:
                    t.is_confirmed = True
                return

        self.technologies.append(tech)
        tech_node_id = f"tech:{tech.technology_name}"
        self.graph.add_node(
            node_id=tech_node_id,
            label=f"{tech.technology_name} ({tech.category})",
            node_type=NodeType.TECHNOLOGY,
            metadata={"version": tech.version, "confirmed": tech.is_confirmed, "confidence": tech.confidence}
        )
        self.graph.add_edge(
            source_id=self.domain_node_id,
            target_id=tech_node_id,
            edge_type=EdgeType.ASSOCIATED_WITH
        )

    def get_summary(self) -> AttackSurfaceSummarySchema:
        """Computes summary statistics across all attack surface dimensions."""
        endpoints = self.endpoint_engine.get_endpoints()
        parameters = self.parameter_engine.get_parameters()
        apis = self.api_engine.get_api_endpoints()
        assets = self.asset_engine.get_assets()

        # Prioritization
        prioritized = self.get_prioritized_endpoints()
        high_pri_count = sum(1 for p in prioritized if p.priority_level.value == "HIGH")

        param_cat_breakdown: Dict[str, int] = {}
        for p in parameters:
            param_cat_breakdown[p.category.value] = param_cat_breakdown.get(p.category.value, 0) + 1

        api_type_breakdown: Dict[str, int] = {}
        for a in apis:
            api_type_breakdown[a.api_type.value] = api_type_breakdown.get(a.api_type.value, 0) + 1

        asset_type_breakdown: Dict[str, int] = {}
        for ass in assets:
            asset_type_breakdown[ass.asset_type.value] = asset_type_breakdown.get(ass.asset_type.value, 0) + 1

        graph_schema = self.graph.to_schema()

        return AttackSurfaceSummarySchema(
            scan_id=self.scan_id,
            target_url=self.target_base_url,
            total_endpoints=len(endpoints),
            total_parameters=len(parameters),
            total_apis=len(apis),
            total_assets=len(assets),
            total_technologies=len(self.technologies),
            graph_nodes_count=graph_schema.node_count,
            graph_edges_count=graph_schema.edge_count,
            high_priority_endpoints_count=high_pri_count,
            parameter_categories_breakdown=param_cat_breakdown,
            api_types_breakdown=api_type_breakdown,
            asset_types_breakdown=asset_type_breakdown
        )

    def get_prioritized_endpoints(self) -> List[PrioritizedEndpointSchema]:
        """Runs prioritization algorithm across all discovered endpoints."""
        endpoints = self.endpoint_engine.get_endpoints()

        params_by_url: Dict[str, List[ParameterIntelligenceSchema]] = {}
        for p in self.parameter_engine.get_parameters():
            for ep_url in p.endpoints_found:
                if ep_url not in params_by_url:
                    params_by_url[ep_url] = []
                params_by_url[ep_url].append(p)

        return DiscoveryPrioritizationEngine.prioritize_all(
            endpoints=endpoints,
            parameters_by_url=params_by_url,
            forms_by_action=self.forms_by_action,
            findings_by_url=self.findings_by_url
        )
