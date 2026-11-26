import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from uuid import uuid4
from fastapi.testclient import TestClient

from backend.app.main import app
from shared.schemas.common import Severity, FindingStatus
from backend.app.scanner.active.models import ActiveFinding

client = TestClient(app)


def test_list_active_analyzers():
    response = client.get("/api/v1/active/analyzers")
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert len(data["data"]) == 8
    analyzer_ids = [a["analyzer_id"] for a in data["data"]]
    assert "ACT-SQLI-ANALYZER" in analyzer_ids
    assert "ACT-XSS-ANALYZER" in analyzer_ids
    assert "ACT-MISCONFIG-ANALYZER" in analyzer_ids
    assert "ACT-SSRF-ANALYZER" in analyzer_ids
    assert "ACT-XXE-ANALYZER" in analyzer_ids
    assert "ACT-AUTH-ANALYZER" in analyzer_ids
    assert "ACT-TRAVERSAL-ANALYZER" in analyzer_ids
    assert "ACT-API-SEC-ANALYZER" in analyzer_ids


def test_list_active_rules():
    response = client.get("/api/v1/active/rules")
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert len(data["data"]) >= 12
    assert "ACT-SQLI-BOOLEAN" in data["data"]
    assert "ACT-XSS-REFLECTED-HTML" in data["data"]


def test_active_probe_safety_gate_rejection():
    # Attempting to probe without authorized=True must fail with 403 Forbidden
    response = client.post(
        "/api/v1/active/probe",
        json={"url": "https://example.com/test", "authorized": False},
    )
    assert response.status_code == 403
    assert "Safety Gate Violation" in response.json()["detail"]


def test_active_probe_authorized_execution():
    mock_finding = ActiveFinding(
        rule_id="ACT-SQLI-ERROR",
        title="SQL Syntax Error",
        description="Database error observed",
        cwe_id="CWE-89",
        owasp_category="A03:2021",
        severity=Severity.HIGH,
        cvss_score=8.5,
        status=FindingStatus.SUSPECTED,
        confidence=0.85,
        url="https://example.com/item",
        parameter="id",
        remediation="Use prepared statements",
        detection_module="ACT-SQLI-ANALYZER",
    )

    with patch(
        "backend.app.scanner.active.engine.ActiveDetectionEngine.run",
        new=AsyncMock(return_value=[mock_finding]),
    ):
        with patch(
            "backend.app.scanner.scope.scope_gate.ScopeGate.validate_url_in_scope",
            return_value=True,
        ):
            response = client.post(
                "/api/v1/active/probe",
                json={
                    "url": "https://example.com/item?id=1",
                    "authorized": True,
                    "request_budget": 10,
                },
            )
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert len(data["data"]) == 1
            assert data["data"][0]["title"] == "SQL Syntax Error"
            assert data["data"][0]["cwe_id"] == "CWE-89"
