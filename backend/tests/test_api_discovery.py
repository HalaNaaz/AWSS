import pytest
from backend.app.scanner.discovery.api_discovery import APIDiscoveryEngine
from shared.schemas.discovery import APIType


def test_api_type_classification():
    engine = APIDiscoveryEngine()

    assert engine.classify_api_type("https://example.com/openapi.json") == APIType.OPENAPI
    assert engine.classify_api_type("https://example.com/api-docs") == APIType.OPENAPI
    assert engine.classify_api_type("https://example.com/graphql") == APIType.GRAPHQL
    assert engine.classify_api_type("https://example.com/ws/events") == APIType.WEBSOCKET
    assert engine.classify_api_type("wss://example.com/socket.io") == APIType.WEBSOCKET
    assert engine.classify_api_type("https://example.com/api/v1/users") == APIType.REST
    assert engine.classify_api_type("https://example.com/search", content_type="application/json") == APIType.JSON_API


def test_api_version_extraction():
    engine = APIDiscoveryEngine()

    assert engine.extract_version("https://example.com/api/v1/orders") == "v1"
    assert engine.extract_version("https://example.com/v2.5/items") == "v2.5"
    assert engine.extract_version("https://example.com/orders") is None


def test_api_endpoint_recording():
    engine = APIDiscoveryEngine()

    # Public REST endpoint
    ep1 = engine.record_api_endpoint(
        url="https://example.com/api/v1/users",
        method="GET",
        status_code=200,
        parameters=["role", "page"]
    )
    assert ep1 is not None
    assert ep1.api_type == APIType.REST
    assert ep1.version == "v1"
    assert not ep1.auth_required

    # Protected REST endpoint (401 status)
    ep2 = engine.record_api_endpoint(
        url="https://example.com/api/v1/admin/keys",
        method="POST",
        status_code=401
    )
    assert ep2 is not None
    assert ep2.auth_required

    assert len(engine.get_api_endpoints()) == 2
    assert len(engine.get_by_type(APIType.REST)) == 2
