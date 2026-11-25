import pytest
from uuid import uuid4

from backend.app.scanner.discovery.endpoint_discovery import AdvancedEndpointDiscovery
from backend.app.scanner.scope.scope_gate import ScopeGate
from shared.schemas.discovery import EndpointCategory, DiscoveryMethod


@pytest.fixture
def target_scope():
    return ScopeGate(target_base_url="https://example.com", allow_private_ips=False)


def test_endpoint_discovery_deduplication(target_scope):
    scan_id = uuid4()
    discovery = AdvancedEndpointDiscovery("https://example.com", target_scope, scan_id)

    # Add same endpoint twice with different query order / casing
    ep1 = discovery.add_endpoint("https://example.com/api/users?b=2&a=1", method="GET")
    ep2 = discovery.add_endpoint("https://example.com/api/users?a=1&b=2", method="GET")

    assert ep1 is not None
    assert ep2 is not None
    assert ep1.normalized_url == ep2.normalized_url
    assert len(discovery.get_endpoints()) == 1


def test_endpoint_discovery_scope_enforcement(target_scope):
    scan_id = uuid4()
    discovery = AdvancedEndpointDiscovery("https://example.com", target_scope, scan_id)

    # Disallow private IPs and external domains
    ep_private = discovery.add_endpoint("http://192.168.1.1/admin")
    ep_external = discovery.add_endpoint("https://attacker.com/evil")
    ep_valid = discovery.add_endpoint("https://example.com/dashboard")

    assert ep_private is None
    assert ep_external is None
    assert ep_valid is not None
    assert len(discovery.get_endpoints()) == 1


def test_endpoint_category_heuristics(target_scope):
    scan_id = uuid4()
    discovery = AdvancedEndpointDiscovery("https://example.com", target_scope, scan_id)

    discovery.add_endpoint("https://example.com/api/v1/data", content_type="application/json")
    discovery.add_endpoint("https://example.com/static/bundle.js")
    discovery.add_endpoint("https://example.com/styles/theme.css")
    discovery.add_endpoint("https://example.com/images/logo.png")
    discovery.add_endpoint("https://example.com/docs/manual.pdf")
    discovery.add_endpoint("https://example.com/ws/live")

    assert len(discovery.get_endpoints_by_category(EndpointCategory.API)) == 1
    assert len(discovery.get_endpoints_by_category(EndpointCategory.JAVASCRIPT)) == 1
    assert len(discovery.get_endpoints_by_category(EndpointCategory.CSS)) == 1
    assert len(discovery.get_endpoints_by_category(EndpointCategory.IMAGE)) == 1
    assert len(discovery.get_endpoints_by_category(EndpointCategory.DOCUMENT)) == 1
    assert len(discovery.get_endpoints_by_category(EndpointCategory.WEBSOCKET)) == 1


def test_endpoint_discovery_confidence_tracking(target_scope):
    scan_id = uuid4()
    discovery = AdvancedEndpointDiscovery("https://example.com", target_scope, scan_id)

    ep_crawler = discovery.add_endpoint("https://example.com/page1", discovery_method=DiscoveryMethod.CRAWLER)
    ep_js = discovery.add_endpoint("https://example.com/page2", discovery_method=DiscoveryMethod.STATIC_JS_ANALYSIS)

    assert ep_crawler.confidence >= 0.90
    assert ep_js.confidence <= 0.85
