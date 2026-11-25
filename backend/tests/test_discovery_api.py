import pytest
from uuid import uuid4
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.scanner.orchestration.scan_orchestrator import scan_registry
from backend.app.scanner.discovery.engine import AttackSurfaceIntelligenceEngine
from backend.app.scanner.scope.scope_gate import ScopeGate
from shared.schemas.discovery import DiscoveredEndpointCreate, PriorityLevel

client = TestClient(app)


@pytest.fixture(autouse=True)
def cleanup_registry():
    scan_registry.clear()
    yield
    scan_registry.clear()


def test_discovery_api_summary_and_subsystems():
    scan_id = uuid4()
    target_url = "https://example.com"
    gate = ScopeGate(target_base_url=target_url, allow_private_ips=True)
    engine = AttackSurfaceIntelligenceEngine(target_url, gate, scan_id)

    # Populate engine telemetry
    engine.ingest_crawled_page(
        url="https://example.com/api/v1/users?role=admin",
        status_code=200,
        content_type="application/json",
        response_size=2048,
        headers={"Server": "nginx/1.20.0"}
    )
    engine.record_finding("Missing Security Headers", "https://example.com/api/v1/users", "LOW")

    scan_registry.register_discovery_engine(scan_id, engine)

    # 1. Summary
    res = client.get(f"/api/v1/discovery/{scan_id}/summary")
    assert res.status_code == 200
    data = res.json()["data"]
    assert data["total_endpoints"] >= 1
    assert data["total_parameters"] >= 1
    assert data["total_apis"] >= 1
    assert data["total_technologies"] >= 1

    # 2. Endpoints
    res = client.get(f"/api/v1/discovery/{scan_id}/endpoints")
    assert res.status_code == 200
    assert len(res.json()["data"]) >= 1

    # 3. Parameters
    res = client.get(f"/api/v1/discovery/{scan_id}/parameters")
    assert res.status_code == 200
    params = res.json()["data"]
    assert any(p["name"] == "role" for p in params)

    # 4. APIs
    res = client.get(f"/api/v1/discovery/{scan_id}/apis")
    assert res.status_code == 200
    apis = res.json()["data"]
    assert len(apis) >= 1

    # 5. Graph
    res = client.get(f"/api/v1/discovery/{scan_id}/graph?graph_format=json")
    assert res.status_code == 200
    graph = res.json()["data"]
    assert graph["node_count"] >= 3

    # 6. Prioritized
    res = client.get(f"/api/v1/discovery/{scan_id}/prioritized")
    assert res.status_code == 200
    assert len(res.json()["data"]) >= 1


def test_discovery_api_not_found():
    unknown_id = uuid4()
    res = client.get(f"/api/v1/discovery/{unknown_id}/summary")
    assert res.status_code == 404
