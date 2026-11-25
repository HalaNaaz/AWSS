import pytest
import socket
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.scanner.scope.scope_gate import ScopeGate
from backend.app.scanner.crawler.client import AsyncHTTPClient, PinningNetworkBackend, PinningTransport
from backend.app.scanner.evidence.redactor import EvidenceRedactor
from backend.app.scanner.active.analyzers.xss import XSSAnalyzer
from backend.app.scanner.active.analyzers.sqli import SQLInjectionAnalyzer
from backend.app.scanner.active.models import ActiveTarget, RequestBudgetTracker
from backend.app.core.exceptions import SSRFValidationError

client = TestClient(app)


# SEC-REQ-01: Client-Supplied Authorization Safety Gate
def test_sec_req_01_mandatory_authorization_confirmation():
    """Unconfirmed probes must be blocked with 403 Forbidden."""
    resp = client.post(
        "/api/v1/active/probe",
        json={"url": "https://target.com/test", "authorized": False},
    )
    assert resp.status_code == 403
    assert "Safety Gate Violation" in resp.json()["detail"]


# SEC-REQ-02: Target Scope & SSRF Enforcement on Probe Endpoint
def test_sec_req_02_scope_enforcement_prevents_private_ip():
    """Probing private IPs or cloud metadata must be rejected with 400 Bad Request."""
    for forbidden_url in [
        "http://127.0.0.1:8080/test",
        "http://10.0.0.1/admin",
        "http://169.254.169.254/latest/meta-data/",
        "http://192.168.1.1/router",
    ]:
        resp = client.post(
            "/api/v1/active/probe",
            json={"url": forbidden_url, "authorized": True},
        )
        assert resp.status_code == 400
        assert "violates ScopeGate" in resp.json()["detail"] or "Safety Gate rejected" in resp.json()["detail"]


# SEC-REQ-03: Socket IP Pinning in AsyncHTTPClient
@pytest.mark.asyncio
async def test_sec_req_03_socket_ip_pinning_in_client():
    """AsyncHTTPClient must populate and use ScopeGate's pin_map for socket connection."""
    scope_gate = ScopeGate(target_base_url="https://app.local", allow_private_ips=True)
    scope_gate.pin_map["app.local"] = "192.0.2.1"

    backend = PinningNetworkBackend(scope_gate.pin_map)
    with patch("httpcore._backends.anyio.AnyIOBackend.connect_tcp", new=AsyncMock()) as mock_connect:
        await backend.connect_tcp("app.local", 443)
        mock_connect.assert_called_once()
        # Verify host argument was translated to pinned IP
        assert mock_connect.call_args[1]["host"] == "192.0.2.1"


# SEC-REQ-04: Multi-record DNS check in ScopeGate
def test_sec_req_04_dns_all_addrinfo_records_checked():
    """If DNS returns dual A/AAAA records with one private, ScopeGate must reject."""
    scope_gate = ScopeGate(target_base_url="http://rebinding.evil.com", allow_private_ips=False)
    
    mock_addrinfo = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80)),
    ]
    with patch("socket.getaddrinfo", return_value=mock_addrinfo):
        with pytest.raises(SSRFValidationError) as exc_info:
            scope_gate.pre_flight_check("http://rebinding.evil.com/secret")
        assert "prohibited" in str(exc_info.value).lower()


# SEC-REQ-05: AsyncHTTPClient supports generic request methods
@pytest.mark.asyncio
async def test_sec_req_05_client_supports_generic_request_methods():
    """AsyncHTTPClient must provide request() method supporting OPTIONS, POST, etc."""
    scope_gate = ScopeGate(target_base_url="https://app.local", allow_private_ips=True)
    async with AsyncHTTPClient(scope_gate=scope_gate) as client_obj:
        assert hasattr(client_obj, "request")
        assert hasattr(client_obj, "post")
        assert hasattr(client_obj, "get")

        # Mock underlying pre_flight and _client.request
        mock_resp = MagicMock(status_code=200, headers={}, text="OK")
        with patch.object(scope_gate, "pre_flight_check", return_value="127.0.0.1"):
            with patch.object(client_obj._client, "request", new=AsyncMock(return_value=mock_resp)):
                resp, err = await client_obj.request("OPTIONS", "https://app.local/api")
                assert err is None
                assert resp.status_code == 200


# SEC-REQ-06: Open Redirect inspection without auto-follow
@pytest.mark.asyncio
async def test_sec_req_06_open_redirect_non_following_behavior():
    """client.request with follow_redirects=False must return the 302 response directly."""
    scope_gate = ScopeGate(target_base_url="https://app.local", allow_private_ips=True)
    async with AsyncHTTPClient(scope_gate=scope_gate) as client_obj:
        mock_redirect = MagicMock(
            status_code=302,
            headers={"Location": "https://evil.com/phish"},
            text="",
        )
        with patch.object(scope_gate, "pre_flight_check", return_value="127.0.0.1"):
            with patch.object(client_obj._client, "request", new=AsyncMock(return_value=mock_redirect)):
                resp, err = await client_obj.request(
                    "GET",
                    "https://app.local/redirect?to=https://evil.com/phish",
                    follow_redirects=False,
                )
                assert err is None
                assert resp.status_code == 302
                assert resp.headers.get("Location") == "https://evil.com/phish"


# SEC-REQ-07: XSS non-HTML MIME rejection prevents false positives
@pytest.mark.asyncio
async def test_sec_req_07_xss_non_html_content_type_no_false_positive():
    """Canary reflection in application/json or text/plain must not trigger HTML XSS."""
    analyzer = XSSAnalyzer()
    target = ActiveTarget(
        url="https://app.local/api/search?q=test",
        method="GET",
        parameters={"q": "test"},
        baseline_status=200,
        baseline_body='{"results": []}',
    )
    
    mock_client = MagicMock()
    # Mock reflection inside JSON payload
    async def mock_get(url):
        import urllib.parse
        parsed = urllib.parse.urlparse(url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        q = params.get("q", "")
        return MagicMock(
            status_code=200,
            text=f'{{"query": "{q}", "results": []}}',
            headers={"content-type": "application/json; charset=utf-8"},
        ), None

    mock_client.get = AsyncMock(side_effect=mock_get)
    budget = RequestBudgetTracker(budget=10)

    findings = await analyzer.check(target, mock_client, budget, uuid4())
    html_findings = [f for f in findings if f.rule_id == "ACT-XSS-REFLECTED-HTML"]
    assert len(html_findings) == 0


# SEC-REQ-08: Evidence Redaction for secrets and cookies
def test_sec_req_08_evidence_redaction_secrets_and_cookies():
    """.env secrets, private keys, and session cookies must be masked."""
    sample_env = "DB_PASSWORD=SuperSecretPass123\nAWS_SECRET_ACCESS_KEY=AKIA123456789\nPORT=8000"
    redacted = EvidenceRedactor.redact(sample_env)
    assert "SuperSecretPass123" not in redacted
    assert "AKIA123456789" not in redacted
    assert "[REDACTED]" in redacted

    sample_cookie = "Set-Cookie: session_id=xyz789abc; Path=/; HttpOnly"
    redacted_cookie = EvidenceRedactor.redact(sample_cookie)
    assert "xyz789abc" not in redacted_cookie
    assert "[REDACTED]" in redacted_cookie


# SEC-REQ-09: SQLi Boolean resists dynamic micro-fluctuations
@pytest.mark.asyncio
async def test_sec_req_09_sqli_boolean_resists_micro_fluctuations():
    """Fluctuations < 15 bytes without status change must not be flagged as verified SQLi."""
    analyzer = SQLInjectionAnalyzer()
    target = ActiveTarget(
        url="https://app.local/news?id=5",
        method="GET",
        parameters={"id": "5"},
        baseline_status=200,
        baseline_body="<html><body>News #5: Welcome. Token: abc</body></html>",
    )
    
    mock_client = MagicMock()
    # Return 1-2 byte difference simulating CSRF token / timestamp drift
    true_resp = MagicMock(
        status_code=200,
        text="<html><body>News #5: Welcome. Token: abc1</body></html>",
        headers={},
    )
    false_resp = MagicMock(
        status_code=200,
        text="<html><body>News #5: Welcome. Token: abc2</body></html>",
        headers={},
    )
    syntax_resp = MagicMock(
        status_code=200,
        text="<html><body>News #5: Welcome. Token: abc3</body></html>",
        headers={},
    )

    mock_client.get = AsyncMock(side_effect=[
        (syntax_resp, None),
        (true_resp, None),
        (false_resp, None),
    ])
    budget = RequestBudgetTracker(budget=10)

    findings = await analyzer.check(target, mock_client, budget, uuid4())
    verified_sqli = [f for f in findings if f.rule_id == "ACT-SQLI-BOOLEAN"]
    assert len(verified_sqli) == 0


# SEC-REQ-10: Probe HTTP method validation
def test_sec_req_10_probe_method_validation():
    """Unsupported probe methods like PATCH or DELETE must be rejected with 400."""
    resp = client.post(
        "/api/v1/active/probe",
        json={
            "url": "https://example.com/api",
            "method": "DELETE",
            "authorized": True,
        },
    )
    assert resp.status_code == 400
    assert "Unsupported HTTP probe method" in resp.json()["detail"]
