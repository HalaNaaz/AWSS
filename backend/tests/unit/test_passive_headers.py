import pytest
from backend.app.scanner.passive.models import HTTPResponseContext
from backend.app.scanner.passive.analyzers.headers import SecurityHeaderAnalyzer
from shared.schemas.common import Severity, FindingStatus


@pytest.fixture
def header_analyzer():
    return SecurityHeaderAnalyzer()


def test_missing_csp_detected_on_html(header_analyzer):
    context = HTTPResponseContext(
        url="https://app.example.com/login",
        status_code=200,
        headers={"Content-Type": "text/html; charset=utf-8"},
        body="<html><body><h1>Login</h1></body></html>"
    )
    findings = header_analyzer.analyze(context)
    rule_ids = [f.rule_id for f in findings]
    assert "PASSIVE-HDR-CSP-MISSING" in rule_ids
    assert "PASSIVE-HDR-XCTO-MISSING" in rule_ids
    assert "PASSIVE-HDR-XFO-MISSING" in rule_ids
    assert "PASSIVE-HDR-REFERRER-MISSING" in rule_ids
    assert "PASSIVE-HDR-PERMISSIONS-MISSING" in rule_ids


def test_csp_unsafe_inline_and_eval_detected(header_analyzer):
    context = HTTPResponseContext(
        url="https://app.example.com/",
        headers={
            "Content-Type": "text/html",
            "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=(), microphone=()",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload"
        }
    )
    findings = header_analyzer.analyze(context)
    rule_ids = [f.rule_id for f in findings]
    assert "PASSIVE-HDR-CSP-UNSAFE" in rule_ids
    assert "PASSIVE-HDR-CSP-MISSING" not in rule_ids


def test_csp_wildcard_script_src(header_analyzer):
    context = HTTPResponseContext(
        url="https://app.example.com/",
        headers={
            "Content-Type": "text/html",
            "Content-Security-Policy": "default-src 'self'; script-src *",
            "X-Content-Type-Options": "nosniff"
        }
    )
    findings = header_analyzer.analyze(context)
    rule_ids = [f.rule_id for f in findings]
    assert "PASSIVE-HDR-CSP-WILDCARD" in rule_ids


def test_csp_missing_default_src(header_analyzer):
    context = HTTPResponseContext(
        url="https://app.example.com/",
        headers={
            "Content-Type": "text/html",
            "Content-Security-Policy": "script-src 'self'; style-src 'self'"
        }
    )
    findings = header_analyzer.analyze(context)
    rule_ids = [f.rule_id for f in findings]
    assert "PASSIVE-HDR-CSP-NO-DEFAULT" in rule_ids


def test_hsts_missing_on_https(header_analyzer):
    context = HTTPResponseContext(
        url="https://secure.example.com/",
        headers={"Content-Type": "text/html"}
    )
    findings = header_analyzer.analyze(context)
    rule_ids = [f.rule_id for f in findings]
    assert "PASSIVE-HDR-HSTS-MISSING" in rule_ids


def test_hsts_short_max_age_and_missing_subdomains(header_analyzer):
    context = HTTPResponseContext(
        url="https://secure.example.com/",
        headers={
            "Content-Type": "text/html",
            "Strict-Transport-Security": "max-age=86400"
        }
    )
    findings = header_analyzer.analyze(context)
    rule_ids = [f.rule_id for f in findings]
    assert "PASSIVE-HDR-HSTS-SHORT-MAXAGE" in rule_ids
    assert "PASSIVE-HDR-HSTS-NO-SUBDOMAINS" in rule_ids


def test_hsts_not_flagged_on_plain_http(header_analyzer):
    # HSTS is only applicable to HTTPS
    context = HTTPResponseContext(
        url="http://insecure.example.com/",
        headers={"Content-Type": "text/html"}
    )
    findings = header_analyzer.analyze(context)
    rule_ids = [f.rule_id for f in findings]
    assert "PASSIVE-HDR-HSTS-MISSING" not in rule_ids


def test_x_frame_options_allow_from_deprecated(header_analyzer):
    context = HTTPResponseContext(
        url="https://app.example.com/",
        headers={
            "Content-Type": "text/html",
            "X-Frame-Options": "ALLOW-FROM https://partner.example.com"
        }
    )
    findings = header_analyzer.analyze(context)
    rule_ids = [f.rule_id for f in findings]
    assert "PASSIVE-HDR-XFO-DEPRECATED" in rule_ids


def test_referrer_policy_unsafe_flagged(header_analyzer):
    context = HTTPResponseContext(
        url="https://app.example.com/",
        headers={
            "Content-Type": "text/html",
            "Referrer-Policy": "unsafe-url"
        }
    )
    findings = header_analyzer.analyze(context)
    rule_ids = [f.rule_id for f in findings]
    assert "PASSIVE-HDR-REFERRER-UNSAFE" in rule_ids


def test_permissions_policy_wildcard_detected(header_analyzer):
    context = HTTPResponseContext(
        url="https://app.example.com/",
        headers={
            "Content-Type": "text/html",
            "Permissions-Policy": "camera=*, microphone=*"
        }
    )
    findings = header_analyzer.analyze(context)
    rule_ids = [f.rule_id for f in findings]
    assert "PASSIVE-HDR-PERMISSIONS-PERMISSIVE" in rule_ids


def test_hsts_preload_directive_check(header_analyzer):
    context = HTTPResponseContext(
        url="https://secure.example.com/",
        headers={
            "Content-Type": "text/html",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains"
        }
    )
    findings = header_analyzer.analyze(context)
    rule_ids = [f.rule_id for f in findings]
    assert "PASSIVE-HDR-HSTS-NO-PRELOAD" in rule_ids
    assert "PASSIVE-HDR-HSTS-SHORT-MAXAGE" not in rule_ids
    assert "PASSIVE-HDR-HSTS-NO-SUBDOMAINS" not in rule_ids


def test_hardened_headers_produce_zero_findings(header_analyzer):
    context = HTTPResponseContext(
        url="https://app.example.com/",
        headers={
            "Content-Type": "text/html",
            "Content-Security-Policy": "default-src 'self'; script-src 'self' 'nonce-r4nd0m'; frame-ancestors 'self'",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=()"
        }
    )
    findings = header_analyzer.analyze(context)
    assert len(findings) == 0
