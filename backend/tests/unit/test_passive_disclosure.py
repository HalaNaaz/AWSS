import pytest
from backend.app.scanner.passive.models import HTTPResponseContext
from backend.app.scanner.passive.analyzers.disclosure import InformationDisclosureAnalyzer
from shared.schemas.common import Severity


@pytest.fixture
def disclosure_analyzer():
    return InformationDisclosureAnalyzer()


def test_server_banner_version_disclosure(disclosure_analyzer):
    context = HTTPResponseContext(
        url="https://app.example.com/",
        headers={"Server": "Apache/2.4.52 (Ubuntu)"}
    )
    findings = disclosure_analyzer.analyze(context)
    rule_ids = [f.rule_id for f in findings]
    assert "PASSIVE-INFO-SERVER-VERSION" in rule_ids


def test_generic_server_banner_not_flagged(disclosure_analyzer):
    # Just "Apache" or "cloudflare" without version is acceptable
    context = HTTPResponseContext(
        url="https://app.example.com/",
        headers={"Server": "cloudflare"}
    )
    findings = disclosure_analyzer.analyze(context)
    rule_ids = [f.rule_id for f in findings]
    assert "PASSIVE-INFO-SERVER-VERSION" not in rule_ids


def test_framework_disclosure_headers(disclosure_analyzer):
    context = HTTPResponseContext(
        url="https://app.example.com/",
        headers={
            "X-Powered-By": "PHP/8.1.2",
            "X-AspNet-Version": "4.0.30319"
        }
    )
    findings = disclosure_analyzer.analyze(context)
    rule_ids = [f.rule_id for f in findings]
    assert "PASSIVE-INFO-FRAMEWORK-DISCLOSURE" in rule_ids


def test_debug_token_headers(disclosure_analyzer):
    context = HTTPResponseContext(
        url="https://app.example.com/",
        headers={
            "X-Debug-Token": "abcdef123456",
            "X-Werkzeug-Pin": "off"
        }
    )
    findings = disclosure_analyzer.analyze(context)
    rule_ids = [f.rule_id for f in findings]
    assert "PASSIVE-INFO-DEBUG-HEADERS" in rule_ids


def test_python_stack_trace_in_body(disclosure_analyzer):
    body = """
    <html>
    <body>
    <h1>500 Internal Server Error</h1>
    <pre>
    Traceback (most recent call last):
      File "/var/app/server.py", line 42, in get_user
        user = db.query(User).filter(User.id == uid).one()
    KeyError: 'id'
    </pre>
    </body>
    </html>
    """
    context = HTTPResponseContext(
        url="https://app.example.com/api/user?id=1",
        status_code=500,
        headers={"Content-Type": "text/html"},
        body=body
    )
    findings = disclosure_analyzer.analyze(context)
    rule_ids = [f.rule_id for f in findings]
    assert "PASSIVE-INFO-STACKTRACE-BODY" in rule_ids
    f = next(f for f in findings if f.rule_id == "PASSIVE-INFO-STACKTRACE-BODY")
    assert f.severity == Severity.HIGH


def test_internal_rfc1918_ip_leak(disclosure_analyzer):
    body = "Cluster Node routing to 10.240.12.55 and backup 192.168.1.100 completed."
    context = HTTPResponseContext(
        url="https://app.example.com/status",
        headers={"Content-Type": "text/plain"},
        body=body
    )
    findings = disclosure_analyzer.analyze(context)
    rule_ids = [f.rule_id for f in findings]
    assert "PASSIVE-INFO-INTERNAL-IP-LEAK" in rule_ids


def test_database_uri_leak(disclosure_analyzer):
    body = "DB init failed: postgres://postgres:SecretPass123@db.internal:5432/production_db"
    context = HTTPResponseContext(
        url="https://app.example.com/db-status",
        status_code=500,
        headers={"Content-Type": "text/plain"},
        body=body
    )
    findings = disclosure_analyzer.analyze(context)
    rule_ids = [f.rule_id for f in findings]
    assert "PASSIVE-INFO-DATABASE-URI-LEAK" in rule_ids
    f = next(f for f in findings if f.rule_id == "PASSIVE-INFO-DATABASE-URI-LEAK")
    assert f.severity == Severity.HIGH
