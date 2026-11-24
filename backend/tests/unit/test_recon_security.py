import pytest
from backend.app.core.exceptions import ScopeViolationError, SSRFValidationError
from backend.app.scanner.scope.scope_gate import ScopeGate
from backend.app.scanner.crawler.client import AsyncHTTPClient


@pytest.mark.asyncio
async def test_crawler_client_blocks_ssrf_loopback():
    """Validates that AsyncHTTPClient blocks requests to loopback addresses."""
    scope_gate = ScopeGate(target_base_url="http://127.0.0.1:8000")
    async with AsyncHTTPClient(scope_gate=scope_gate) as client:
        resp, err = await client.get("http://127.0.0.1:8000/api")
        assert resp is None
        assert err is not None
        assert "RFC 1918" in err or "Cloud Metadata" in err or "Restricted" in err or "Prohibited" in err or "Gate" in err


@pytest.mark.asyncio
async def test_crawler_client_blocks_cloud_metadata():
    """Validates that requests targeting 169.254.169.254 are aborted prior to socket creation."""
    scope_gate = ScopeGate(target_base_url="http://169.254.169.254")
    async with AsyncHTTPClient(scope_gate=scope_gate) as client:
        resp, err = await client.get("http://169.254.169.254/latest/meta-data/")
        assert resp is None
        assert err is not None


@pytest.mark.asyncio
async def test_crawler_client_blocks_out_of_scope_url():
    """Validates that out-of-scope URLs are rejected before dispatch."""
    scope_gate = ScopeGate(target_base_url="https://authorized.example.com")
    async with AsyncHTTPClient(scope_gate=scope_gate) as client:
        resp, err = await client.get("https://unauthorized-victim.com/admin")
        assert resp is None
        assert "scope" in err.lower()


def test_scope_gate_redirect_to_private_subnet():
    """Validates that a redirect hop targeting an RFC 1918 address is aborted."""
    gate = ScopeGate(target_base_url="https://authorized.example.com")
    with pytest.raises(ScopeViolationError):
        # Redirecting to private IP is out-of-scope and rejected
        gate.validate_redirect("http://10.0.0.1/internal-dashboard")
