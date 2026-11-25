import pytest
from backend.app.scanner.discovery.js_analyzer import JSStaticIntelligenceAnalyzer
from backend.app.scanner.scope.scope_gate import ScopeGate


@pytest.fixture
def scope_gate():
    return ScopeGate(target_base_url="https://example.com", allow_private_ips=True)


def test_js_static_intelligence_extraction(scope_gate):
    sample_js = """
    // Route configs
    const routes = [
      { path: '/dashboard' },
      { path: '/admin/settings' },
      { path: '/upload/avatar' }
    ];

    function fetchData() {
      fetch('/api/v1/users?role=admin');
      axios.post('/rest/checkout', { token: 'secret_val', order_id: 1234 });
      new URL('/v2/metrics', window.location);
    }

    const socket = new WebSocket('wss://example.com/ws/notifications');
    const legacyIo = io('/socket.io/data');

    //# sourceMappingURL=/static/app.bundle.js.map
    """

    result = JSStaticIntelligenceAnalyzer.analyze_js(
        js_content=sample_js,
        base_url="https://example.com",
        scope_gate=scope_gate
    )

    # 1. API routes detected
    assert any("/api/v1/users" in ep for ep in result.endpoints)
    assert any("/rest/checkout" in ep for ep in result.endpoints)
    assert any("/v2/metrics" in ep for ep in result.endpoints)
    assert len(result.api_routes) >= 2

    # 2. Sensitive / Admin routes flagged
    assert any("/admin/settings" in r for r in result.sensitive_routes)
    assert any("/upload/avatar" in r for r in result.sensitive_routes)

    # 3. WebSockets detected
    assert len(result.websocket_urls) >= 1
    assert any("wss://example.com/ws/notifications" in ws for ws in result.websocket_urls)

    # 4. Parameters extracted from query or object literals
    assert "role" in result.parameter_names or "order_id" in result.parameter_names

    # 5. Sourcemap detected
    assert any("app.bundle.js.map" in sm for sm in result.sourcemap_urls)


def test_js_static_intelligence_zero_dynamic_execution(scope_gate):
    # Malicious JS containing dynamic eval or side effects
    malicious_js = """
    var x = 1;
    // this would throw or cause side effect if dynamically evaluated
    throw new Error('DANGER');
    """
    # Static analysis must safely parse and not execute or crash
    result = JSStaticIntelligenceAnalyzer.analyze_js(
        js_content=malicious_js,
        base_url="https://example.com",
        scope_gate=scope_gate
    )
    assert isinstance(result.endpoints, set)
