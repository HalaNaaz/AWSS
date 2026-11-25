import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.api.v1.endpoints.active import register_verified_target
from backend.app.scanner.discovery.js_analyzer import JSStaticIntelligenceAnalyzer
from backend.app.scanner.discovery.parameter_intelligence import ParameterIntelligenceEngine
from backend.app.scanner.discovery.attack_surface_graph import AttackSurfaceGraph
from backend.app.scanner.discovery.prioritizer import DiscoveryPrioritizationEngine
from backend.app.scanner.discovery.engine import AttackSurfaceIntelligenceEngine
from backend.app.scanner.orchestration.scan_orchestrator import ScanOrchestrator, scan_registry
from backend.app.scanner.scope.scope_gate import ScopeGate
from shared.schemas.common import Severity, ScanProfile, ScanStatus
from shared.schemas.discovery import (
    NodeType,
    EdgeType,
    DiscoveredEndpointCreate,
    DiscoveryMethod,
    ParameterCategory,
    ParameterLocation,
)

client = TestClient(app)


# ==============================================================================
# SECTION 1: PHASE 3 REMEDIATION & AUTHORIZATION SAFEGUARDS
# ==============================================================================

def test_phase3_target_ownership_enforcement():
    """Verify that target_id lookups enforce verified ownership and scope boundaries."""
    # 1. Non-existent target ID must return 404
    missing_id = uuid4()
    resp = client.post(
        "/api/v1/active/probe",
        json={
            "url": "https://example.com/test",
            "target_id": str(missing_id),
            "authorized": True,
        },
    )
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()

    # 2. Unverified target ID must return 403
    unverified_id = uuid4()
    register_verified_target(
        target_id=unverified_id,
        base_url="https://unverified.target.com",
        name="Unverified Corp",
        verified=False,
    )
    resp = client.post(
        "/api/v1/active/probe",
        json={
            "url": "https://unverified.target.com/profile",
            "target_id": str(unverified_id),
            "authorized": True,
        },
    )
    assert resp.status_code == 403
    assert "ownership has not been verified" in resp.json()["detail"].lower()

    # 3. Verified target ID with out-of-scope URL must return 400
    verified_id = uuid4()
    register_verified_target(
        target_id=verified_id,
        base_url="https://authorized.app.local",
        name="Authorized App",
        verified=True,
    )
    resp = client.post(
        "/api/v1/active/probe",
        json={
            "url": "https://attacker-controlled.com/evil",
            "target_id": str(verified_id),
            "authorized": True,
        },
    )
    assert resp.status_code == 400
    assert "outside authorized scope" in resp.json()["detail"].lower()


def test_phase3_probe_prohibits_put_method():
    """Verify that HTTP PUT is rejected to prevent state-mutating resource overwrites."""
    resp = client.post(
        "/api/v1/active/probe",
        json={
            "url": "https://example.com/upload",
            "method": "PUT",
            "authorized": True,
        },
    )
    assert resp.status_code == 400
    assert "Unsupported HTTP probe method 'PUT'" in resp.json()["detail"]


# ==============================================================================
# SECTION 2: PHASE 4 SCAN ORCHESTRATION & TELEMETRY REGISTRATION
# ==============================================================================

@pytest.mark.asyncio
async def test_phase4_scan_orchestrator_registers_discovery_engine():
    """Verify that ScanOrchestrator registers discovery_engine with scan_registry for API telemetry."""
    scan_id = uuid4()
    target_url = "https://app.local"
    orchestrator = ScanOrchestrator(
        target_url=target_url,
        scan_id=scan_id,
        profile=ScanProfile.QUICK_ASSESSMENT,
        max_crawl_depth=1,
        max_urls=5,
    )

    # Mock the crawler run so we don't send real network requests
    with patch("backend.app.scanner.crawler.crawler.AsyncCrawler.crawl", new=AsyncMock(return_value=[])):
        with patch("backend.app.scanner.crawler.client.AsyncHTTPClient.get", new=AsyncMock(return_value=(MagicMock(status_code=200, headers={}, text="<html>Home</html>"), None))):
            with patch("backend.app.scanner.scope.scope_gate.ScopeGate.pre_flight_check", return_value="127.0.0.1"):
                await orchestrator.run()

    # Verify discovery engine was registered in scan_registry
    registered_engine = scan_registry.get_discovery_engine(scan_id)
    assert registered_engine is not None
    assert registered_engine.scan_id == scan_id

    # Verify discovery summary endpoint returns data for this scan
    resp = client.get(f"/api/v1/discovery/{scan_id}/summary")
    assert resp.status_code == 200
    assert resp.json()["success"] is True
    assert "total_endpoints" in resp.json()["data"]


# ==============================================================================
# SECTION 3: PHASE 4 STATIC JS INTELLIGENCE & BOUNDED EXECUTION
# ==============================================================================

def test_phase4_js_analyzer_max_size_cap():
    """Verify that JS analyzer caps input size to MAX_JS_ANALYSIS_SIZE to prevent ReDoS / memory exhaustion."""
    scope_gate = ScopeGate(target_base_url="https://app.local", allow_private_ips=True)
    
    # Create oversized JS content > 2MB
    oversized_js = "var apiRoute = '/api/v1/users';\n" * 100_000
    assert len(oversized_js) > JSStaticIntelligenceAnalyzer.MAX_JS_ANALYSIS_SIZE

    # Run analyzer - must complete quickly and safely
    result = JSStaticIntelligenceAnalyzer.analyze_js(
        js_content=oversized_js,
        base_url="https://app.local",
        scope_gate=scope_gate,
    )
    assert len(result.endpoints) >= 1
    assert any("/api/v1/users" in ep for ep in result.endpoints)


def test_phase4_zero_dynamic_js_execution():
    """Verify that malicious JS scripts with eval or process exit are never executed."""
    scope_gate = ScopeGate(target_base_url="https://app.local", allow_private_ips=True)
    malicious_js = """
    // Malicious payload attempting dynamic execution
    eval("throw new Error('DYNAMIC_EVAL_TRIGGERED')");
    window.location = "https://evil.com";
    fetch("/api/v2/keys");
    """

    result = JSStaticIntelligenceAnalyzer.analyze_js(
        js_content=malicious_js,
        base_url="https://app.local",
        scope_gate=scope_gate,
    )
    # If dynamic eval ran, it would throw an exception. Statically, it extracts '/api/v2/keys'
    assert any("/api/v2/keys" in ep for ep in result.endpoints)


# ==============================================================================
# SECTION 4: PHASE 4 PARAMETER INTELLIGENCE & REDACTION
# ==============================================================================

def test_phase4_parameter_intelligence_redaction():
    """Verify that AUTH, SESSION, and SENSITIVE parameters are strictly redacted."""
    engine = ParameterIntelligenceEngine()

    p_auth = engine.record_parameter(
        name="access_token",
        location=ParameterLocation.QUERY,
        endpoint_url="https://app.local/oauth",
        sample_value="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secretpayload",
    )
    assert p_auth.category == ParameterCategory.AUTH
    assert p_auth.sample_values_redacted == ["[REDACTED]"]

    p_card = engine.record_parameter(
        name="credit_card",
        location=ParameterLocation.BODY,
        endpoint_url="https://app.local/checkout",
        sample_value="4111222233334444",
    )
    assert p_card.category == ParameterCategory.SENSITIVE
    assert p_card.sample_values_redacted == ["[REDACTED]"]


# ==============================================================================
# SECTION 5: PHASE 4 API BOUNDS & PAGINATION
# ==============================================================================

def test_phase4_discovery_api_pagination():
    """Verify that discovery API endpoints honor limit and offset parameters."""
    scan_id = uuid4()
    scope_gate = ScopeGate(target_base_url="https://app.local", allow_private_ips=True)
    intel_engine = AttackSurfaceIntelligenceEngine(
        target_base_url="https://app.local",
        scope_gate=scope_gate,
        scan_id=scan_id,
    )

    # Ingest 15 endpoints
    for i in range(15):
        intel_engine.endpoint_engine.add_endpoint(
            raw_url=f"https://app.local/page_{i}",
            method="GET",
            discovery_method=DiscoveryMethod.CRAWLER,
        )

    scan_registry.register_discovery_engine(scan_id, intel_engine)

    # Test pagination: limit=5, offset=0
    resp_page1 = client.get(f"/api/v1/discovery/{scan_id}/endpoints?limit=5&offset=0")
    assert resp_page1.status_code == 200
    data_page1 = resp_page1.json()["data"]
    assert len(data_page1) == 5

    # Test pagination: limit=5, offset=5
    resp_page2 = client.get(f"/api/v1/discovery/{scan_id}/endpoints?limit=5&offset=5")
    assert resp_page2.status_code == 200
    data_page2 = resp_page2.json()["data"]
    assert len(data_page2) == 5
    # Ensure disjoint sets
    page1_urls = {ep["url"] for ep in data_page1}
    page2_urls = {ep["url"] for ep in data_page2}
    assert len(page1_urls.intersection(page2_urls)) == 0


# ==============================================================================
# SECTION 6: PHASE 4 ATTACK SURFACE GRAPH BOUNDS & FINDING LINKAGE
# ==============================================================================

def test_phase4_attack_surface_graph_bounds():
    """Verify that the AttackSurfaceGraph strictly respects MAX_NODES and MAX_EDGES."""
    graph = AttackSurfaceGraph(scan_id=uuid4(), max_nodes=100, max_edges=100)

    # Attempt to add 150 nodes
    for i in range(150):
        graph.add_node(f"node_{i}", f"Node {i}", NodeType.ENDPOINT)
    assert len(graph._nodes) == 100

    # Attempt to add 150 edges
    for i in range(149):
        graph.add_edge(f"node_{i}", f"node_{i+1}", EdgeType.LINKS_TO)
    assert len(graph._edges) <= 100


def test_phase4_graph_finding_post_method_linkage():
    """Verify that record_finding links to endpoint nodes whether method is GET, POST, or other."""
    scan_id = uuid4()
    scope_gate = ScopeGate(target_base_url="https://app.local", allow_private_ips=True)
    intel_engine = AttackSurfaceIntelligenceEngine(
        target_base_url="https://app.local",
        scope_gate=scope_gate,
        scan_id=scan_id,
    )

    # Add a POST endpoint node
    post_ep_url = "https://app.local/api/login"
    intel_engine.graph.add_node(
        node_id=f"ep:{post_ep_url}:POST",
        label=f"POST {post_ep_url}",
        node_type=NodeType.ENDPOINT,
    )

    # Record finding against this POST endpoint
    intel_engine.record_finding(
        finding_title="Cleartext Login Transmission",
        endpoint_url=post_ep_url,
        severity="HIGH",
    )

    # Verify edge was created
    edges = list(intel_engine.graph._edges.values())
    finding_edges = [e for e in edges if e.edge_type == EdgeType.HAS_FINDING]
    assert len(finding_edges) == 1
    assert finding_edges[0].source == f"ep:{post_ep_url}:POST"


# ==============================================================================
# SECTION 7: PHASE 4 PRIORITIZATION SCORE BOUNDS
# ==============================================================================

def test_phase4_prioritization_score_bounds():
    """Verify exploration priority scores remain strictly within [0.0, 100.0]."""
    ep = DiscoveredEndpointCreate(
        scan_id=uuid4(),
        url="https://app.local/admin/upload",
        normalized_url="https://app.local/admin/upload",
        method="POST",
        status_code=500,
    )
    # Extreme scenario: all signals fired + 5 findings
    schema = DiscoveryPrioritizationEngine.prioritize_endpoint(
        endpoint=ep,
        parameters=[
            MagicMock(category=ParameterCategory.FILE),
            MagicMock(category=ParameterCategory.REDIRECT),
            MagicMock(category=ParameterCategory.IDENTIFIER),
        ],
        has_form=True,
        findings_count=10,
    )
    assert 0.0 <= schema.priority_score <= 100.0
    assert schema.priority_level.value == "HIGH"
