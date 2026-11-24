import pytest
from unittest.mock import AsyncMock, patch
from uuid import uuid4
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from backend.app.main import app
from shared.schemas.common import Severity, FindingStatus
from shared.schemas.discovery import ReconSummaryResponse
from shared.schemas.finding import FindingResponse, EndpointSchema, EvidenceSchema
from backend.app.scanner.orchestration.scan_orchestrator import scan_registry


@pytest.fixture
def client():
    scan_registry.clear()
    return TestClient(app)


@pytest.fixture
def mock_recon():
    scan_id = uuid4()
    findings = [
        FindingResponse(
            id=uuid4(),
            scan_id=scan_id,
            title="Missing CSP",
            description="Content Security Policy missing",
            severity=Severity.HIGH,
            confidence=0.9,
            status=FindingStatus.SUSPECTED,
            cwe_id="CWE-693",
            cvss_score=7.5,
            remediation="Add Content-Security-Policy header",
            endpoint=EndpointSchema(url="https://api.test/home", method="GET"),
            evidence=EvidenceSchema(
                request="GET /home HTTP/1.1",
                response="HTTP/1.1 200 OK",
                sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            created_at=datetime.now(timezone.utc),
        )
    ]
    return ReconSummaryResponse(
        scan_id=scan_id,
        target_url="https://api.test",
        status="COMPLETED",
        urls_crawled=5,
        endpoints_discovered=4,
        forms_discovered=1,
        technologies_detected=0,
        crawl_depth_reached=2,
        execution_time_seconds=1.2,
        categories_breakdown={"API": 4},
        technologies=[],
        findings_count=1,
        findings=findings,
    )


def test_create_and_get_scan_job_sync(client: TestClient, mock_recon):
    with patch(
        "backend.app.scanner.orchestration.scan_orchestrator.ReconOrchestrator.run",
        new=AsyncMock(return_value=mock_recon),
    ):
        response = client.post(
            "/api/v1/scans/?run_sync=true",
            json={
                "target_url": "https://api.test",
                "profile": "QUICK_ASSESSMENT",
                "max_crawl_depth": 2,
                "max_urls": 50,
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["success"] is True
        scan_id = data["data"]["id"]
        assert data["data"]["target_url"] == "https://api.test"
        assert data["data"]["status"] == "COMPLETED"
        assert data["data"]["findings_count"] == 1

        # Retrieve status
        status_resp = client.get(f"/api/v1/scans/{scan_id}")
        assert status_resp.status_code == 200
        assert status_resp.json()["data"]["id"] == scan_id

        # Retrieve findings
        findings_resp = client.get(f"/api/v1/scans/{scan_id}/findings")
        assert findings_resp.status_code == 200
        findings_data = findings_resp.json()["data"]
        assert len(findings_data) == 1
        assert findings_data[0]["title"] == "Missing CSP"

        # Retrieve report via /scans/{id}/report
        report_json_resp = client.get(f"/api/v1/scans/{scan_id}/report?format=json")
        assert report_json_resp.status_code == 200
        assert "Missing CSP" in report_json_resp.text

        # Retrieve report via /reports/{id}?format=html
        report_html_resp = client.get(f"/api/v1/reports/{scan_id}?format=html")
        assert report_html_resp.status_code == 200
        assert "<!DOCTYPE html>" in report_html_resp.text

        # Retrieve report via /reports/{id}?format=markdown
        report_md_resp = client.get(f"/api/v1/reports/{scan_id}?format=markdown")
        assert report_md_resp.status_code == 200
        assert "# Ashlynx WebSec Scanner" in report_md_resp.text


def test_cancel_scan_job(client: TestClient):
    response = client.post(
        "/api/v1/scans/",
        json={"target_url": "https://cancel-test.com", "profile": "SAFE_MODE"},
    )
    assert response.status_code == 201
    scan_id = response.json()["data"]["id"]

    cancel_resp = client.post(f"/api/v1/scans/{scan_id}/cancel")
    assert cancel_resp.status_code == 200
    assert cancel_resp.json()["data"]["status"] == "CANCELLED"


def test_scan_not_found(client: TestClient):
    random_id = uuid4()
    resp = client.get(f"/api/v1/scans/{random_id}")
    assert resp.status_code == 404

    rep_resp = client.get(f"/api/v1/reports/{random_id}")
    assert rep_resp.status_code == 404
