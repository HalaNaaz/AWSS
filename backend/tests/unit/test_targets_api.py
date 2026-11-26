from uuid import uuid4
import pytest
from fastapi.testclient import TestClient

from backend.app.core.config import settings
from backend.app.main import app
from backend.app.api.v1.endpoints.targets import target_registry, DEFAULT_CONTROLLED_TARGET_ID
from backend.app.api.v1.endpoints.active import _VERIFIED_TARGETS


@pytest.fixture
def client():
    target_registry.clear(reseed=True)
    return TestClient(app)


def test_list_targets_includes_seeded_controlled_target(client: TestClient):
    resp = client.get("/api/v1/targets/")
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["success"] is True
    targets = payload["data"]
    assert len(targets) >= 1
    assert any(t["id"] == str(DEFAULT_CONTROLLED_TARGET_ID) for t in targets)


def test_create_get_and_delete_target_lifecycle(client: TestClient):
    create_resp = client.post(
        "/api/v1/targets/",
        json={
            "name": "Staging App",
            "base_url": "https://staging.example.com/",
            "description": "Pre-release staging application",
            "asset_criticality": 4.0,
        },
    )
    assert create_resp.status_code == 201
    created = create_resp.json()["data"]
    target_id = created["id"]
    assert created["name"] == "Staging App"
    assert created["base_url"] == "https://staging.example.com"
    assert created["scope_rules"][0]["pattern"] == "https://staging.example.com/*"
    assert created["verified"] is True

    # Registered for active module verification
    assert target_id in {str(k) for k in _VERIFIED_TARGETS.keys()}

    # Retrieve single target
    get_resp = client.get(f"/api/v1/targets/{target_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["data"]["name"] == "Staging App"

    # Delete target
    del_resp = client.delete(f"/api/v1/targets/{target_id}")
    assert del_resp.status_code == 200
    assert del_resp.json()["data"]["status"] == "DELETED"

    # Verify deleted
    assert client.get(f"/api/v1/targets/{target_id}").status_code == 404


def test_target_validation_rejects_invalid_and_ssrf_urls(client: TestClient, monkeypatch):
    monkeypatch.setattr(settings, "ALLOW_PRIVATE_IPS", False)

    assert client.post("/api/v1/targets/", json={"name": " ", "base_url": "https://example.com"}).status_code == 422
    assert client.post("/api/v1/targets/", json={"name": "Bad Scheme", "base_url": "javascript:alert(1)"}).status_code == 422
    assert client.post("/api/v1/targets/", json={"name": "File URI", "base_url": "file:///etc/passwd"}).status_code == 422
    assert client.post("/api/v1/targets/", json={"name": "Loopback", "base_url": "http://127.0.0.1:8080"}).status_code == 422
    assert client.post("/api/v1/targets/", json={"name": "Metadata", "base_url": "http://169.254.169.254"}).status_code == 422


def test_target_not_found_returns_404(client: TestClient):
    missing = uuid4()
    assert client.get(f"/api/v1/targets/{missing}").status_code == 404
    assert client.delete(f"/api/v1/targets/{missing}").status_code == 404
