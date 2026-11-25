import pytest
from uuid import uuid4

from backend.app.scanner.discovery.engine import AttackSurfaceIntelligenceEngine
from backend.app.scanner.discovery.endpoint_discovery import AdvancedEndpointDiscovery
from backend.app.scanner.discovery.asset_inventory import AssetInventoryManager
from backend.app.scanner.discovery.api_discovery import APIDiscoveryEngine
from backend.app.scanner.discovery.parameter_intelligence import ParameterIntelligenceEngine
from backend.app.scanner.discovery.prioritizer import DiscoveryPrioritizationEngine
from backend.app.scanner.discovery.technology_fingerprinter import AdvancedTechnologyFingerprinter
from backend.app.scanner.scope.scope_gate import ScopeGate
from shared.schemas.discovery import (
    EndpointCategory,
    AssetType,
    APIType,
    ParameterLocation,
    ParameterCategory,
    PriorityLevel
)


@pytest.fixture
def scope_gate():
    return ScopeGate(target_base_url="https://example.com", allow_private_ips=True)


def test_engine_full_lifecycle_coverage(scope_gate):
    scan_id = uuid4()
    target_url = "https://example.com"
    engine = AttackSurfaceIntelligenceEngine(target_url, scope_gate, scan_id)

    # 1. Ingest crawled pages of various categories
    ep1 = engine.ingest_crawled_page(
        url="https://example.com/api/v1/users?role=admin&page=1&redirect_to=/home",
        status_code=200,
        content_type="application/json",
        response_size=1024,
        headers={"Server": "nginx", "X-Powered-By": "Express"},
        body='{"users": []}',
        source_url="https://example.com"
    )
    assert ep1 is not None

    ep_asset = engine.ingest_crawled_page(
        url="https://example.com/static/style.css",
        status_code=200,
        content_type="text/css",
        response_size=512,
        source_url="https://example.com"
    )
    assert ep_asset is not None

    # 2. Ingest forms
    engine.ingest_form(
        action_url="https://example.com/login",
        method="POST",
        fields=[
            {"name": "username", "default_value": "user"},
            {"name": "password", "default_value": "secret"}
        ],
        source_url="https://example.com/login"
    )

    # 3. Ingest JavaScript
    sample_js = """
    fetch('/api/v2/items?cat=gadgets');
    const ws = new WebSocket('/ws/stream');
    const sensitive = '/admin/billing';
    //# sourceMappingURL=/static/bundle.js.map
    """
    js_result = engine.ingest_javascript(sample_js, "https://example.com/static/bundle.js")
    assert len(js_result.endpoints) >= 1

    # 4. Record findings
    engine.record_finding("SQL Injection Vulnerability", "https://example.com/api/v1/users", "HIGH")

    # 5. Get Prioritized Endpoints
    prioritized = engine.get_prioritized_endpoints()
    assert len(prioritized) >= 2
    assert prioritized[0].priority_score >= prioritized[1].priority_score

    # 6. Get Summary
    summary = engine.get_summary()
    assert summary.total_endpoints >= 2
    assert summary.total_parameters >= 2
    assert summary.total_apis >= 1
    assert summary.total_assets >= 1
    assert summary.graph_nodes_count >= 5
    assert summary.graph_edges_count >= 3


def test_asset_inventory_mime_types():
    manager = AssetInventoryManager(max_assets=100)

    # Test MIME branches
    assert manager.categorize_asset("https://example.com/asset1", content_type="application/javascript") == AssetType.JAVASCRIPT
    assert manager.categorize_asset("https://example.com/asset2", content_type="text/css") == AssetType.CSS
    assert manager.categorize_asset("https://example.com/asset3", content_type="image/png") == AssetType.IMAGE
    assert manager.categorize_asset("https://example.com/asset4", content_type="font/woff2") == AssetType.FONT
    assert manager.categorize_asset("https://example.com/asset5", content_type="application/pdf") == AssetType.DOCUMENT
    assert manager.categorize_asset("https://example.com/unknown", content_type="unknown/other") == AssetType.OTHER

    # Record and filter by type
    manager.record_asset("https://example.com/logo.png", content_type="image/png")
    images = manager.get_by_type(AssetType.IMAGE)
    assert len(images) == 1


def test_endpoint_discovery_mime_and_edge_cases(scope_gate):
    scan_id = uuid4()
    discovery = AdvancedEndpointDiscovery("https://example.com", scope_gate, scan_id)

    # Content type heuristics
    discovery.add_endpoint("https://example.com/feed", content_type="application/xml")
    discovery.add_endpoint("https://example.com/stream", content_type="text/xml")
    discovery.add_endpoint("https://example.com/app", content_type="application/javascript")
    discovery.add_endpoint("https://example.com/download", content_type="application/octet-stream")

    apis = discovery.get_endpoints_by_category(EndpointCategory.API)
    assert len(apis) >= 2


def test_api_discovery_rpc_and_edge_cases():
    engine = APIDiscoveryEngine()

    assert engine.classify_api_type("https://example.com/rpc/v1") == APIType.RPC
    assert engine.classify_api_type("https://example.com/grpc/service") == APIType.RPC
    assert engine.classify_api_type("https://example.com/jsonrpc") == APIType.RPC

    # Test update existing API endpoint
    ep1 = engine.record_api_endpoint("https://example.com/api/v1/orders", method="GET", confidence=0.8)
    ep2 = engine.record_api_endpoint("https://example.com/api/v1/orders", method="GET", status_code=401, confidence=0.9, parameters=["id"])
    assert ep2.auth_required
    assert ep2.confidence == 0.9
    assert "id" in ep2.parameters


def test_parameter_intelligence_edge_cases():
    engine = ParameterIntelligenceEngine()

    # Empty name should raise ValueError
    with pytest.raises(ValueError):
        engine.record_parameter("", ParameterLocation.QUERY, "https://example.com")

    # Long sample value truncation
    long_val = "A" * 60
    sanitized = engine.sanitize_value(ParameterCategory.SEARCH, long_val)
    assert len(sanitized) <= 40
    assert sanitized.endswith("...")

    # Filter by category
    engine.record_parameter("q", ParameterLocation.QUERY, "https://example.com")
    searches = engine.get_by_category(ParameterCategory.SEARCH)
    assert len(searches) >= 1


def test_technology_fingerprint_additional_headers():
    scan_id = uuid4()
    headers = {
        "CF-Ray": "123456789",
        "X-Drupal-Cache": "HIT",
        "X-Varnish": "987654321",
        "Fastly-Restarts": "1",
        "Set-Cookie": "connect.sid=s%3A123; ASP.NET_SessionId=xyz;"
    }
    techs = AdvancedTechnologyFingerprinter.fingerprint(scan_id, headers)
    tech_names = [t.technology_name for t in techs]

    assert "Cloudflare" in tech_names
    assert "Drupal" in tech_names
    assert "Varnish" in tech_names
    assert "Fastly" in tech_names
    assert "Express" in tech_names
    assert "ASP.NET" in tech_names
