import re
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from shared.schemas.discovery import (
    APIType,
    APIEndpointSchema
)


class APIDiscoveryEngine:
    """API Discovery and classification engine.
    
    Identifies REST, GraphQL, OpenAPI/Swagger specifications, JSON APIs, WebSockets,
    and RPC endpoints, parsing version patterns and tracking authentication requirements.
    
    DEFENSIVE INVARIANT: Strictly read-only inspection; no GraphQL mutation fuzzing
    and no unauthorized schema brute-forcing.
    """

    VERSION_PATTERN = re.compile(r"/(v\d+(?:\.\d+)?)/", re.IGNORECASE)

    OPENAPI_PATHS = [
        "/openapi.json",
        "/swagger.json",
        "/api-docs",
        "/v2/api-docs",
        "/v3/api-docs",
        "/docs",
        "/redoc",
        "/swagger/v1/swagger.json",
        "/api/swagger.json"
    ]

    GRAPHQL_PATHS = [
        "/graphql",
        "/gql",
        "/v1/graphql",
        "/api/graphql"
    ]

    WEBSOCKET_PATHS = [
        "/ws",
        "/wss",
        "/socket.io",
        "/cable",
        "/realtime",
        "/stream"
    ]

    def __init__(self):
        # Map: (url, method) -> APIEndpointSchema
        self._api_endpoints: Dict[Tuple[str, str], APIEndpointSchema] = {}

    @classmethod
    def extract_version(cls, url: str) -> Optional[str]:
        """Extracts API version identifier from URL path if present."""
        path = urlparse(url).path
        match = cls.VERSION_PATTERN.search(path)
        if match:
            return match.group(1).lower()
        return None

    @classmethod
    def classify_api_type(cls, url: str, content_type: Optional[str] = None) -> APIType:
        """Classifies the API architectural pattern based on URL pattern and content type."""
        parsed = urlparse(url)
        path = parsed.path.lower()

        # WebSocket protocol or paths
        if parsed.scheme in ("ws", "wss"):
            return APIType.WEBSOCKET
        for wsp in cls.WEBSOCKET_PATHS:
            if wsp in path:
                return APIType.WEBSOCKET

        # OpenAPI / Swagger
        for oap in cls.OPENAPI_PATHS:
            if path.endswith(oap) or oap in path:
                return APIType.OPENAPI

        # GraphQL
        for gqp in cls.GRAPHQL_PATHS:
            if path == gqp or path.endswith(gqp):
                return APIType.GRAPHQL

        # RPC
        if "/rpc" in path or "/jsonrpc" in path or "/grpc" in path:
            return APIType.RPC

        # REST vs JSON API
        if any(prefix in path for prefix in ("/api/", "/rest/", "/v1/", "/v2/", "/v3/")):
            return APIType.REST

        if content_type and "application/json" in content_type.lower():
            return APIType.JSON_API

        return APIType.OTHER

    def record_api_endpoint(
        self,
        url: str,
        method: str = "GET",
        content_type: Optional[str] = None,
        status_code: Optional[int] = None,
        parameters: Optional[List[str]] = None,
        discovery_source: str = "CRAWLER",
        confidence: float = 0.85
    ) -> Optional[APIEndpointSchema]:
        """Evaluates an endpoint; if it represents an API, records it into the API inventory."""
        api_type = self.classify_api_type(url, content_type)
        if api_type == APIType.OTHER and not any(p in url.lower() for p in ("/api/", "/rest/", "/json")):
            return None

        method_upper = method.upper().strip()
        key = (url, method_upper)

        version = self.extract_version(url)
        auth_required = False
        if status_code in (401, 403):
            auth_required = True
        elif any(token in url.lower() for token in ("/admin/", "/secure/", "/auth/", "/private/")):
            auth_required = True

        param_list = parameters or []

        if key in self._api_endpoints:
            existing = self._api_endpoints[key]
            if auth_required:
                existing.auth_required = True
            for p in param_list:
                if p not in existing.parameters:
                    existing.parameters.append(p)
            if confidence > existing.confidence:
                existing.confidence = confidence
            return existing

        endpoint = APIEndpointSchema(
            url=url,
            method=method_upper,
            api_type=api_type,
            version=version,
            auth_required=auth_required,
            parameters=param_list,
            discovery_source=discovery_source,
            confidence=confidence
        )
        self._api_endpoints[key] = endpoint
        return endpoint

    def get_api_endpoints(self) -> List[APIEndpointSchema]:
        """Returns all discovered API endpoints."""
        return list(self._api_endpoints.values())

    def get_by_type(self, api_type: APIType) -> List[APIEndpointSchema]:
        """Filters API endpoints by API type."""
        return [ep for ep in self._api_endpoints.values() if ep.api_type == api_type]
