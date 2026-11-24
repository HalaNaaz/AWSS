import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_health_check_endpoint(async_client: AsyncClient):
    response = await async_client.get("/api/v1/healthz")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "HEALTHY"
    assert "Ashlynx" in data["service"]


@pytest.mark.asyncio
async def test_root_liveness_endpoint(async_client: AsyncClient):
    response = await async_client.get("/healthz")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "HEALTHY"


@pytest.mark.asyncio
async def test_readiness_check_endpoint(async_client: AsyncClient):
    response = await async_client.get("/api/v1/readyz")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "READY"
    assert data["checks"]["scope_gate"] == "OPERATIONAL"
