from dataclasses import dataclass, field
import re
from typing import Set, List, Optional
from urllib.parse import urlparse

from backend.app.scanner.crawler.normalizer import URLNormalizer
from backend.app.scanner.scope.scope_gate import ScopeGate


@dataclass
class JSAnalysisResult:
    """Structured results from static JavaScript bundle analysis."""
    endpoints: Set[str] = field(default_factory=set)
    api_routes: Set[str] = field(default_factory=set)
    websocket_urls: Set[str] = field(default_factory=set)
    parameter_names: Set[str] = field(default_factory=set)
    sensitive_routes: Set[str] = field(default_factory=set)
    sourcemap_urls: Set[str] = field(default_factory=set)


class JSStaticIntelligenceAnalyzer:
    """Analyzes client-side JavaScript bundles using purely static lexical and pattern analysis.
    
    CRITICAL INVARIANT: Zero dynamic code evaluation (no eval, no execution of untrusted scripts).
    Extracts candidate routes, API paths, WebSocket targets, parameter names, sensitive endpoints,
    and sourcemap references.
    """

    # API route patterns in JS source code
    API_PATTERNS = [
        re.compile(r"""['"`](/(?:api|v[1-9]|rest|graphql|oauth|auth|users?|account|admin|billing)/[\w\-/{}.]+)['"`]""", re.IGNORECASE),
        re.compile(r"""fetch\s*\(\s*['"`]([^'"`\s]+)['"`]""", re.IGNORECASE),
        re.compile(r"""axios\.(?:get|post|put|delete|patch|request)\s*\(\s*['"`]([^'"`\s]+)['"`]""", re.IGNORECASE),
        re.compile(r"""\$\.(?:ajax|get|post|getJSON)\s*\(\s*['"`]([^'"`\s]+)['"`]""", re.IGNORECASE),
        re.compile(r"""path\s*:\s*['"`](/[a-zA-Z0-9_\-/]+)['"`]""", re.IGNORECASE),
        re.compile(r"""new\s+URL\s*\(\s*['"`](/[^'"`\s]+)['"`]""", re.IGNORECASE),
        re.compile(r"""url\s*:\s*['"`](/[a-zA-Z0-9_\-/{}.]+)['"`]""", re.IGNORECASE),
        re.compile(r"""endpoint\s*:\s*['"`](/[a-zA-Z0-9_\-/{}.]+)['"`]""", re.IGNORECASE),
    ]

    # WebSocket patterns
    WEBSOCKET_PATTERNS = [
        re.compile(r"""new\s+WebSocket\s*\(\s*['"`](wss?://[^'"`\s]+|/[^'"`\s]+)['"`]""", re.IGNORECASE),
        re.compile(r"""io\s*\(\s*['"`](wss?://[^'"`\s]+|/[^'"`\s]+)['"`]""", re.IGNORECASE),
        re.compile(r"""['"`](wss?://[^\s'"`]+)['"`]""", re.IGNORECASE),
    ]

    # Parameter name extraction patterns
    PARAM_PATTERNS = [
        re.compile(r"""[?&]([a-zA-Z0-9_\-]+)=[^&\s'"`,;)]*"""),
        re.compile(r"""params\s*:\s*\{\s*([a-zA-Z0-9_\s:,{}"']+)""", re.IGNORECASE),
        re.compile(r"""searchParams\.(?:get|set|has|append)\s*\(\s*['"`]([a-zA-Z0-9_\-]+)['"`]""", re.IGNORECASE),
        re.compile(r"""URLSearchParams\s*\(\s*['"`]([^'"`]+)['"`]""", re.IGNORECASE),
    ]

    # High-risk / sensitive route indicators
    SENSITIVE_ROUTE_PATTERNS = [
        re.compile(r"""/(?:admin|internal|debug|test|backup|config|metrics|actuator|manage|upload|portal)/[\w\-/{}.]*""", re.IGNORECASE),
        re.compile(r"""/(?:reset-password|forgot-password|change-password|mfa|2fa|otp|impersonate)""", re.IGNORECASE),
    ]

    # SourceMappingURL patterns
    SOURCEMAP_PATTERN = re.compile(r"""(?:/\*#\s*sourceMappingURL=([^\s*]+)\s*\*\/|//#\s*sourceMappingURL=([^\s]+))""")

    @classmethod
    def analyze_js(cls, js_content: str, base_url: str, scope_gate: ScopeGate) -> JSAnalysisResult:
        """Performs static intelligence extraction on JavaScript source code.
        
        Args:
            js_content: Raw JavaScript content.
            base_url: Target base URL for resolving relative paths.
            scope_gate: ScopeGate instance for validating in-scope endpoints.
            
        Returns:
            JSAnalysisResult containing discovered endpoints, routes, parameters, and metadata.
        """
        result = JSAnalysisResult()
        if not js_content or not isinstance(js_content, str):
            return result

        # 1. Extract API & Candidate Route Endpoints
        for pattern in cls.API_PATTERNS:
            for match in pattern.findall(js_content):
                endpoint_str = match.strip()
                if endpoint_str.endswith((".png", ".jpg", ".svg", ".css", ".ico", ".woff", ".woff2", ".ttf")):
                    continue
                if len(endpoint_str) < 2 or " " in endpoint_str or "\n" in endpoint_str:
                    continue

                normalized = URLNormalizer.normalize_url(endpoint_str, base_url)
                if normalized and scope_gate.validate_url_in_scope(normalized):
                    result.endpoints.add(normalized)
                    if any(prefix in normalized.lower() for prefix in ("/api/", "/v1/", "/v2/", "/v3/", "/rest/", "/graphql")):
                        result.api_routes.add(normalized)

        # 2. Extract WebSocket Endpoints
        for pattern in cls.WEBSOCKET_PATTERNS:
            for match in pattern.findall(js_content):
                ws_str = match.strip()
                if ws_str.startswith(("ws://", "wss://")):
                    result.websocket_urls.add(ws_str)
                elif ws_str.startswith("/"):
                    # Convert to ws/wss based on base_url
                    parsed_base = urlparse(base_url)
                    ws_scheme = "wss" if parsed_base.scheme == "https" else "ws"
                    ws_url = f"{ws_scheme}://{parsed_base.netloc}{ws_str}"
                    result.websocket_urls.add(ws_url)

        # 3. Extract Parameter Names
        for pattern in cls.PARAM_PATTERNS:
            for match in pattern.findall(js_content):
                if isinstance(match, str):
                    # If it's a params object or raw query string
                    if "=" in match:
                        for part in match.split("&"):
                            if "=" in part:
                                key = part.split("=")[0].strip("?&'\" ")
                                if key and re.match(r"^[a-zA-Z0-9_\-]+$", key) and len(key) <= 64:
                                    result.parameter_names.add(key)
                    elif ":" in match:
                        # Extract keys from JS object literal snippet: foo: 1, bar: "baz"
                        keys = re.findall(r"""(['"]?[a-zA-Z0-9_\-]+['"]?)\s*:""", match)
                        for k in keys:
                            clean_k = k.strip("'\" ")
                            if clean_k and re.match(r"^[a-zA-Z0-9_\-]+$", clean_k) and len(clean_k) <= 64:
                                result.parameter_names.add(clean_k)
                    else:
                        clean_param = match.strip("'\" ")
                        if clean_param and re.match(r"^[a-zA-Z0-9_\-]+$", clean_param) and len(clean_param) <= 64:
                            result.parameter_names.add(clean_param)

        # 4. Check for Sensitive Routes
        for ep in result.endpoints:
            parsed_ep = urlparse(ep)
            for sens_pat in cls.SENSITIVE_ROUTE_PATTERNS:
                if sens_pat.search(parsed_ep.path):
                    result.sensitive_routes.add(ep)

        # 5. Extract Source Maps
        for match in cls.SOURCEMAP_PATTERN.findall(js_content):
            sm_ref = match[0] or match[1]
            if sm_ref:
                clean_sm = sm_ref.strip()
                if not clean_sm.startswith("data:"):
                    norm_sm = URLNormalizer.normalize_url(clean_sm, base_url)
                    if norm_sm:
                        result.sourcemap_urls.add(norm_sm)

        return result
