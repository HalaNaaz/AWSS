import pytest
from backend.app.scanner.passive.models import HTTPResponseContext
from backend.app.scanner.passive.analyzers.https_config import HTTPSConfigAnalyzer
from backend.app.scanner.passive.analyzers.html_security import HTMLSecurityAnalyzer
from shared.schemas.common import Severity


@pytest.fixture
def https_analyzer():
    return HTTPSConfigAnalyzer()


@pytest.fixture
def html_analyzer():
    return HTMLSecurityAnalyzer()


def test_https_analyzer_cleartext_http(https_analyzer):
    context = HTTPResponseContext(
        url="http://insecure.example.com/dashboard",
        headers={"Content-Type": "text/html"}
    )
    findings = https_analyzer.analyze(context)
    rule_ids = [f.rule_id for f in findings]
    assert "PASSIVE-HTTPS-INSECURE-SCHEME" in rule_ids


def test_https_analyzer_insecure_redirect_downgrade(https_analyzer):
    context = HTTPResponseContext(
        url="https://secure.example.com/checkout",
        status_code=302,
        headers={"Location": "http://insecure.example.com/login"}
    )
    findings = https_analyzer.analyze(context)
    rule_ids = [f.rule_id for f in findings]
    assert "PASSIVE-HTTPS-INSECURE-REDIRECT" in rule_ids
    f = next(f for f in findings if f.rule_id == "PASSIVE-HTTPS-INSECURE-REDIRECT")
    assert f.severity == Severity.HIGH


def test_https_analyzer_mixed_content_detection(https_analyzer):
    html = """
    <html>
      <head>
        <script src="http://cdn.example.com/lib.js"></script>
        <link rel="stylesheet" href="http://cdn.example.com/style.css">
      </head>
      <body>
        <img src="http://media.example.com/photo.jpg">
      </body>
    </html>
    """
    context = HTTPResponseContext(
        url="https://secure.example.com/page",
        headers={"Content-Type": "text/html"},
        body=html
    )
    findings = https_analyzer.analyze(context)
    rule_ids = [f.rule_id for f in findings]
    assert "PASSIVE-HTTPS-ACTIVE-MIXED-CONTENT" in rule_ids
    assert "PASSIVE-HTTPS-PASSIVE-MIXED-CONTENT" in rule_ids


def test_html_analyzer_missing_charset_and_viewport(html_analyzer):
    html = "<html><head><title>Test</title></head><body>Hello</body></html>"
    context = HTTPResponseContext(
        url="https://app.example.com/",
        headers={"Content-Type": "text/html"},
        body=html
    )
    findings = html_analyzer.analyze(context)
    rule_ids = [f.rule_id for f in findings]
    assert "PASSIVE-HTML-MISSING-CHARSET" in rule_ids
    assert "PASSIVE-HTML-MISSING-VIEWPORT" in rule_ids


def test_html_analyzer_external_scripts_without_sri(html_analyzer):
    html = """
    <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
      </head>
      <body></body>
    </html>
    """
    context = HTTPResponseContext(
        url="https://app.example.com/",
        headers={"Content-Type": "text/html"},
        body=html
    )
    findings = html_analyzer.analyze(context)
    rule_ids = [f.rule_id for f in findings]
    assert "PASSIVE-HTML-SRI-MISSING" in rule_ids


def test_html_analyzer_form_cleartext_action_and_password(html_analyzer):
    html = """
    <html>
      <head><meta charset="utf-8"></head>
      <body>
        <form action="http://insecure.example.com/submit" method="POST">
          <input type="text" name="username">
          <input type="password" name="password">
          <button type="submit">Login</button>
        </form>
      </body>
    </html>
    """
    context = HTTPResponseContext(
        url="https://secure.example.com/login",
        headers={"Content-Type": "text/html"},
        body=html
    )
    findings = html_analyzer.analyze(context)
    rule_ids = [f.rule_id for f in findings]
    assert "PASSIVE-HTML-FORM-CLEAR-ACTION" in rule_ids
    assert "PASSIVE-HTML-FORM-PASSWORD-CLEAR" in rule_ids
    assert "PASSIVE-HTML-FORM-NO-CSRF-TOKEN" in rule_ids


def test_charset_in_content_type_header_suppresses_meta_charset(html_analyzer):
    html = "<html><head><meta name='viewport' content='width=device-width'></head><body>Hello</body></html>"
    context = HTTPResponseContext(
        url="https://app.example.com/",
        headers={"Content-Type": "text/html; charset=utf-8"},
        body=html
    )
    findings = html_analyzer.analyze(context)
    rule_ids = [f.rule_id for f in findings]
    assert "PASSIVE-HTML-MISSING-CHARSET" not in rule_ids


def test_csrf_external_form_action_not_flagged(html_analyzer):
    html = """
    <html>
      <head><meta charset="utf-8"><meta name="viewport" content="width=device-width"></head>
      <body>
        <form action="https://www.google.com/search" method="POST">
          <input type="text" name="q">
          <button type="submit">Search</button>
        </form>
      </body>
    </html>
    """
    context = HTTPResponseContext(
        url="https://app.example.com/",
        headers={"Content-Type": "text/html"},
        body=html
    )
    findings = html_analyzer.analyze(context)
    rule_ids = [f.rule_id for f in findings]
    assert "PASSIVE-HTML-FORM-NO-CSRF-TOKEN" not in rule_ids


def test_html_analyzer_sensitive_comments(html_analyzer):
    html = """
    <html>
      <head><meta charset="utf-8"></head>
      <body>
        <!-- TODO: fix password hash before deploy -->
        <!-- admin portal located at /internal_admin_panel -->
      </body>
    </html>
    """
    context = HTTPResponseContext(
        url="https://app.example.com/",
        headers={"Content-Type": "text/html"},
        body=html
    )
    findings = html_analyzer.analyze(context)
    rule_ids = [f.rule_id for f in findings]
    assert "PASSIVE-HTML-SENSITIVE-COMMENT" in rule_ids
