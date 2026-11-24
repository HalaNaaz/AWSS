import pytest
from backend.app.scanner.passive.models import HTTPResponseContext
from backend.app.scanner.passive.analyzers.cors import CORSAnalyzer
from shared.schemas.common import Severity


@pytest.fixture
def cors_analyzer():
    return CORSAnalyzer()


def test_cors_wildcard_with_credentials(cors_analyzer):
    context = HTTPResponseContext(
        url="https://api.example.com/user/profile",
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true"
        }
    )
    findings = cors_analyzer.analyze(context)
    rule_ids = [f.rule_id for f in findings]
    assert "PASSIVE-CORS-WILDCARD-WITH-CREDENTIALS" in rule_ids
    f = next(f for f in findings if f.rule_id == "PASSIVE-CORS-WILDCARD-WITH-CREDENTIALS")
    assert f.severity == Severity.HIGH


def test_cors_null_origin(cors_analyzer):
    context = HTTPResponseContext(
        url="https://api.example.com/data",
        headers={
            "Access-Control-Allow-Origin": "null"
        }
    )
    findings = cors_analyzer.analyze(context)
    rule_ids = [f.rule_id for f in findings]
    assert "PASSIVE-CORS-NULL-ORIGIN" in rule_ids


def test_cors_wildcard_on_api_endpoint(cors_analyzer):
    context = HTTPResponseContext(
        url="https://api.example.com/v1/items",
        headers={
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*"
        }
    )
    findings = cors_analyzer.analyze(context)
    rule_ids = [f.rule_id for f in findings]
    assert "PASSIVE-CORS-WILDCARD-ORIGIN" in rule_ids


def test_cors_wildcard_methods(cors_analyzer):
    context = HTTPResponseContext(
        url="https://api.example.com/v1/resource",
        headers={
            "Access-Control-Allow-Origin": "https://trusted.example.com",
            "Access-Control-Allow-Methods": "*"
        }
    )
    findings = cors_analyzer.analyze(context)
    rule_ids = [f.rule_id for f in findings]
    assert "PASSIVE-CORS-OVERLY-PERMISSIVE-METHODS" in rule_ids


def test_secure_cors_produces_zero_findings(cors_analyzer):
    context = HTTPResponseContext(
        url="https://api.example.com/v1/data",
        headers={
            "Access-Control-Allow-Origin": "https://dashboard.example.com",
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS"
        }
    )
    findings = cors_analyzer.analyze(context)
    assert len(findings) == 0
