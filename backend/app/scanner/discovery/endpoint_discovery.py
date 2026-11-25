import re
from typing import List, Dict, Any, Optional, Set, Tuple
from urllib.parse import urlparse
from uuid import UUID

from backend.app.scanner.crawler.normalizer import URLNormalizer, EXTENSION_CATEGORIES
from backend.app.scanner.scope.scope_gate import ScopeGate
from shared.schemas.discovery import (
    DiscoveredEndpointCreate,
    EndpointCategory,
    DiscoveryMethod
)


class AdvancedEndpointDiscovery:
    """Advanced endpoint discovery and deduplication engine.
    
    Extracts and validates endpoints from HTML markup, redirects, stylesheets,
    sitemaps, robots.txt, and static JavaScript bundles with strict ScopeGate enforcement.
    """

    CONFIDENCE_BY_METHOD = {
        DiscoveryMethod.CRAWLER: 0.95,
        DiscoveryMethod.FORM_ACTION: 0.95,
        DiscoveryMethod.HTML_REDIRECT: 0.90,
        DiscoveryMethod.ROBOTS_TXT: 0.85,
        DiscoveryMethod.SITEMAP_XML: 0.85,
        DiscoveryMethod.STATIC_JS_ANALYSIS: 0.80,
        DiscoveryMethod.JAVASCRIPT_AST: 0.80,
        DiscoveryMethod.API_SPEC: 0.90,
        DiscoveryMethod.HEADER_METADATA: 0.75,
    }

    def __init__(self, target_base_url: str, scope_gate: ScopeGate, scan_id: UUID):
        self.target_base_url = target_base_url
        self.scope_gate = scope_gate
        self.scan_id = scan_id
        # Map: (normalized_url, method) -> DiscoveredEndpointCreate
        self._endpoints: Dict[Tuple[str, str], DiscoveredEndpointCreate] = {}

    @classmethod
    def categorize_url(cls, url: str, content_type: Optional[str] = None) -> EndpointCategory:
        """Determines the endpoint category from URL extension, path pattern, or MIME type."""
        parsed = urlparse(url)
        path = parsed.path.lower()

        # Check WebSocket schemes
        if parsed.scheme in ("ws", "wss"):
            return EndpointCategory.WEBSOCKET

        # Check Content-Type header if available
        if content_type:
            ct = content_type.lower()
            if "application/json" in ct or "application/xml" in ct or "text/xml" in ct:
                return EndpointCategory.API
            if "javascript" in ct:
                return EndpointCategory.JAVASCRIPT
            if "text/css" in ct:
                return EndpointCategory.CSS
            if "image/" in ct:
                return EndpointCategory.IMAGE
            if "application/pdf" in ct or "application/zip" in ct or "application/octet-stream" in ct:
                return EndpointCategory.DOCUMENT

        # Check file extension mapping
        for ext, category in EXTENSION_CATEGORIES.items():
            if path.endswith(ext):
                return category

        # Path heuristics
        if any(p in path for p in ("/api/", "/rest/", "/graphql", "/v1/", "/v2/", "/v3/", "/json/")):
            return EndpointCategory.API
        if any(p in path for p in ("/ws", "/socket.io", "/cable")):
            return EndpointCategory.WEBSOCKET

        return EndpointCategory.PAGE

    def add_endpoint(
        self,
        raw_url: str,
        method: str = "GET",
        discovery_method: DiscoveryMethod = DiscoveryMethod.CRAWLER,
        source_url: Optional[str] = None,
        status_code: Optional[int] = None,
        content_type: Optional[str] = None,
        response_size: Optional[int] = None,
        response_time_ms: Optional[float] = None,
        crawl_depth: int = 0,
        query_params: Optional[Dict[str, Any]] = None,
        confidence: Optional[float] = None
    ) -> Optional[DiscoveredEndpointCreate]:
        """Normalizes, validates scope, and deduplicates an endpoint."""
        normalized = URLNormalizer.normalize_url(raw_url, self.target_base_url)
        if not normalized or not URLNormalizer.is_valid_url(normalized):
            return None

        # ScopeGate strict validation
        if not self.scope_gate.validate_url_in_scope(normalized):
            return None

        method_upper = method.upper().strip()
        key = (normalized, method_upper)

        conf = confidence if confidence is not None else self.CONFIDENCE_BY_METHOD.get(discovery_method, 0.8)
        category = self.categorize_url(normalized, content_type)

        if key in self._endpoints:
            existing = self._endpoints[key]
            # Update telemetry if newer or richer
            if status_code is not None and existing.status_code is None:
                existing.status_code = status_code
            if content_type is not None and existing.content_type is None:
                existing.content_type = content_type
                existing.endpoint_category = self.categorize_url(normalized, content_type)
            if response_size is not None and existing.response_size is None:
                existing.response_size = response_size
            if response_time_ms is not None and existing.response_time_ms is None:
                existing.response_time_ms = response_time_ms
            if conf > existing.confidence:
                existing.confidence = conf
            return existing

        endpoint = DiscoveredEndpointCreate(
            scan_id=self.scan_id,
            url=raw_url,
            normalized_url=normalized,
            method=method_upper,
            status_code=status_code,
            content_type=content_type,
            response_size=response_size,
            response_time_ms=response_time_ms,
            source_url=source_url,
            discovery_method=discovery_method,
            crawl_depth=crawl_depth,
            endpoint_category=category,
            query_params=query_params,
            confidence=conf
        )
        self._endpoints[key] = endpoint
        return endpoint

    def get_endpoints(self) -> List[DiscoveredEndpointCreate]:
        """Returns all deduplicated discovered endpoints."""
        return list(self._endpoints.values())

    def get_endpoints_by_category(self, category: EndpointCategory) -> List[DiscoveredEndpointCreate]:
        """Filters discovered endpoints by category."""
        return [ep for ep in self._endpoints.values() if ep.endpoint_category == category]
