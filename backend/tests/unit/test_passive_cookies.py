import pytest
from backend.app.scanner.passive.models import HTTPResponseContext
from backend.app.scanner.passive.analyzers.cookies import CookieSecurityAnalyzer
from shared.schemas.common import Severity


@pytest.fixture
def cookie_analyzer():
    return CookieSecurityAnalyzer()


def test_cookie_missing_secure_on_https(cookie_analyzer):
    context = HTTPResponseContext(
        url="https://app.example.com/",
        headers={
            "Set-Cookie": "session_id=abc123456; Path=/; HttpOnly; SameSite=Lax"
        }
    )
    findings = cookie_analyzer.analyze(context)
    rule_ids = [f.rule_id for f in findings]
    assert "PASSIVE-COOKIE-SECURE-MISSING" in rule_ids
    assert "PASSIVE-COOKIE-HTTPONLY-MISSING" not in rule_ids


def test_cookie_missing_httponly_on_sensitive_token(cookie_analyzer):
    context = HTTPResponseContext(
        url="https://app.example.com/",
        headers={
            "Set-Cookie": "auth_token=jwt.eyJhbGci.secret; Path=/; Secure; SameSite=Strict"
        }
    )
    findings = cookie_analyzer.analyze(context)
    rule_ids = [f.rule_id for f in findings]
    assert "PASSIVE-COOKIE-HTTPONLY-MISSING" in rule_ids
    assert "PASSIVE-COOKIE-SECURE-MISSING" not in rule_ids


def test_cookie_missing_samesite(cookie_analyzer):
    context = HTTPResponseContext(
        url="https://app.example.com/",
        headers={
            "Set-Cookie": "sid=xyz987; Path=/; Secure; HttpOnly"
        }
    )
    findings = cookie_analyzer.analyze(context)
    rule_ids = [f.rule_id for f in findings]
    assert "PASSIVE-COOKIE-SAMESITE-MISSING" in rule_ids


def test_cookie_samesite_none_without_secure(cookie_analyzer):
    context = HTTPResponseContext(
        url="https://app.example.com/",
        headers={
            "Set-Cookie": "tracking_id=track1; Path=/; SameSite=None"
        }
    )
    findings = cookie_analyzer.analyze(context)
    rule_ids = [f.rule_id for f in findings]
    assert "PASSIVE-COOKIE-SAMESITE-NONE-INSECURE" in rule_ids


def test_cookie_excessive_max_age(cookie_analyzer):
    context = HTTPResponseContext(
        url="https://app.example.com/",
        headers={
            "Set-Cookie": "session=sess123; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=63072000"
        }
    )
    findings = cookie_analyzer.analyze(context)
    rule_ids = [f.rule_id for f in findings]
    assert "PASSIVE-COOKIE-EXCESSIVE-MAXAGE" in rule_ids


def test_cookie_plaintext_http_transmission(cookie_analyzer):
    context = HTTPResponseContext(
        url="http://insecure.example.com/login",
        headers={
            "Set-Cookie": "session_id=secret123; Path=/; HttpOnly"
        }
    )
    findings = cookie_analyzer.analyze(context)
    rule_ids = [f.rule_id for f in findings]
    assert "PASSIVE-COOKIE-PLAINTEXT-TRANSMISSION" in rule_ids
    f = next(f for f in findings if f.rule_id == "PASSIVE-COOKIE-PLAINTEXT-TRANSMISSION")
    assert f.severity == Severity.HIGH


def test_cookie_deletion_directive_suppressed(cookie_analyzer):
    # Cookies being invalidated with Max-Age=0 or 1970 expiry should not produce missing security flag noise
    context = HTTPResponseContext(
        url="https://app.example.com/logout",
        headers={
            "Set-Cookie": "session_id=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0"
        }
    )
    findings = cookie_analyzer.analyze(context)
    assert len(findings) == 0


def test_fully_hardened_cookie_produces_zero_findings(cookie_analyzer):
    context = HTTPResponseContext(
        url="https://app.example.com/",
        headers={
            "Set-Cookie": "session_id=secret123; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=28800"
        }
    )
    findings = cookie_analyzer.analyze(context)
    assert len(findings) == 0
