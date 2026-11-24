import pytest
from uuid import uuid4
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_recon_api_lifecycle(async_client: AsyncClient):
    target_id = uuid4()
    
    # 1. Start Recon Job
    start_payload = {
        "target_id": str(target_id),
        "max_crawl_depth": 2,
        "max_urls": 100,
        "concurrency": 4,
        "rate_limit_rps": 5.0,
        "analyze_javascript": True,
        "respect_robots": True
    }
    start_resp = await async_client.post("/api/v1/recon/start", json=start_payload)
    assert start_resp.status_code == 201
    start_data = start_resp.json()
    assert start_data["success"] is True
    scan_id = start_data["data"]["scan_id"]

    # 2. Query Status
    status_resp = await async_client.get(f"/api/v1/recon/{scan_id}/status")
    assert status_resp.status_code == 200
    status_data = status_resp.json()
    assert status_data["data"]["scan_id"] == scan_id

    # 3. Query Endpoints
    endpoints_resp = await async_client.get(f"/api/v1/recon/{scan_id}/endpoints")
    assert endpoints_resp.status_code == 200
    endpoints_data = endpoints_resp.json()
    assert "items" in endpoints_data

    # 4. Query Technologies
    tech_resp = await async_client.get(f"/api/v1/recon/{scan_id}/technologies")
    assert tech_resp.status_code == 200

    # 5. Cancel Job
    cancel_resp = await async_client.post(f"/api/v1/recon/{scan_id}/cancel")
    assert cancel_resp.status_code == 200
    cancel_data = cancel_resp.json()
    assert cancel_data["data"]["status"] == "CANCELLED"
