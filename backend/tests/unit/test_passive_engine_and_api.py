import pytest
from uuid import uuid4
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.scanner.passive.engine import PassiveAnalysisEngine
from backend.app.scanner.passive.models import HTTPResponseContext


@pytest.fixture
def test_client():
    return TestClient(app)


def test_passive_engine_rules_and_analyzers_listing():
    engine = PassiveAnalysisEngine()
    analyzers = engine.list_analyzers()
    assert len(analyzers) >= 6
    rules = engine.list_all_rules()
    assert len(rules) >= 20
    assert "PASSIVE-HDR-CSP-MISSING" in rules
    assert "PASSIVE-COOKIE-SECURE-MISSING" in rules
    assert "PASSIVE-CORS-WILDCARD-WITH-CREDENTIALS" in rules
    assert "PASSIVE-INFO-STACKTRACE-BODY" in rules
    assert "PASSIVE-HTTPS-ACTIVE-MIXED-CONTENT" in rules
    assert "PASSIVE-HTML-SRI-MISSING" in rules


def test_passive_engine_batching_and_deduplication():
    engine = PassiveAnalysisEngine()
    ctx1 = HTTPResponseContext(
        url="https://app.example.com/page1",
        headers={"Content-Type": "text/html"}
    )
    ctx2 = HTTPResponseContext(
        url="https://app.example.com/page1",  # duplicate url
        headers={"Content-Type": "text/html"}
    )
    findings = engine.analyze_batch([ctx1, ctx2])
    # Ensure deduplicated
    keys = [(f.rule_id, f.url, f.parameter) for f in findings]
    assert len(keys) == len(set(keys))
    # Evidence seal integrity
    for f in findings:
        assert len(f.evidence_hash) == 64  # SHA-256


def test_api_list_analyzers(test_client):
    response = test_client.get("/api/v1/passive/analyzers")
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert len(data["data"]) >= 6
    analyzer_names = [a["name"] for a in data["data"]]
    assert "Security Header Policy Analyzer" in analyzer_names


def test_api_list_rules(test_client):
    response = test_client.get("/api/v1/passive/rules")
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert len(data["data"]) >= 20


def test_api_analyze_endpoint(test_client):
    scan_id = str(uuid4())
    payload = {
        "url": "https://app.example.com/profile",
        "status_code": 200,
        "headers": {
            "Content-Type": "text/html",
            "Server": "Apache/2.4.49 (Unix)",
            "Set-Cookie": "session_id=secret123; Path=/"
        },
        "body": "<html><body><!-- TODO: remove admin test key --></body></html>",
        "method": "GET",
        "scan_id": scan_id
    }
    response = test_client.post("/api/v1/passive/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    findings = data["data"]
    assert len(findings) > 0

    rule_ids = [f["endpoint"]["headers"]["evidence_rule"] for f in findings]
    assert "PASSIVE-INFO-SERVER-VERSION" in rule_ids
    assert "PASSIVE-COOKIE-SECURE-MISSING" in rule_ids
    assert "PASSIVE-HTML-SENSITIVE-COMMENT" in rule_ids

    # Query via /api/v1/passive/{scan_id}/findings
    get_resp = test_client.get(f"/api/v1/passive/{scan_id}/findings")
    assert get_resp.status_code == 200
    items = get_resp.json()["items"]
    assert len(items) == len(findings)
