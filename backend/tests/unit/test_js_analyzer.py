import pytest
from backend.app.scanner.reconnaissance.js_analyzer import JavaScriptEndpointExtractor
from backend.app.scanner.scope.scope_gate import ScopeGate


def test_js_analyzer_endpoint_extraction():
    scope_gate = ScopeGate(target_base_url="https://app.example.com")
    base_url = "https://app.example.com"

    js_code = """
    function fetchUserData(userId) {
        return fetch('/api/v1/users/' + userId);
    }
    const adminUrl = "/admin/settings";
    axios.get("/api/v2/reports");
    const accountUrl = '/account/profile';
    const extUrl = 'https://external-api.com/v1/auth';
    const ignoreImg = '/static/images/logo.png';
    """

    endpoints = JavaScriptEndpointExtractor.extract_endpoints(js_code, base_url, scope_gate)

    assert "https://app.example.com/api/v1/users" in endpoints or any("/api/v1/users" in e for e in endpoints)
    assert "https://app.example.com/admin/settings" in endpoints
    assert "https://app.example.com/api/v2/reports" in endpoints
    assert "https://app.example.com/account/profile" in endpoints

    # Out of scope domain should NOT be included
    assert not any("external-api.com" in e for e in endpoints)

    # Static images should NOT be included
    assert not any(e.endswith(".png") for e in endpoints)
