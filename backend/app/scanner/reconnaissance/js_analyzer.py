import re
from typing import Set, List
from backend.app.scanner.crawler.normalizer import URLNormalizer
from backend.app.scanner.scope.scope_gate import ScopeGate


class JavaScriptEndpointExtractor:
    """Extracts candidate API routes and endpoint paths from client-side JavaScript bundles."""

    # Regex patterns matching API endpoints and route definitions in JS source code
    ENDPOINT_PATTERNS = [
        # Explicit relative API paths: '/api/v1/users', '/rest/items'
        re.compile(r"""['"`](/(?:api|v\d+|rest|graphql|oauth|auth|users?|account|admin)/[\w\-/{}.]+)['"`]""", re.IGNORECASE),
        # Fetch calls: fetch('/endpoint') or fetch("https://...")
        re.compile(r"""fetch\s*\(\s*['"`]([^'"`]+)['"`]""", re.IGNORECASE),
        # Axios calls: axios.get('/endpoint')
        re.compile(r"""axios\.(?:get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]""", re.IGNORECASE),
        # Angular / Vue router path definitions: path: '/dashboard'
        re.compile(r"""path\s*:\s*['"`](/[a-zA-Z0-9_\-/]+)['"`]""", re.IGNORECASE),
        # URL constructor: new URL('/api/...', window.location)
        re.compile(r"""new\s+URL\s*\(\s*['"`](/[^'"`]+)['"`]""", re.IGNORECASE),
    ]

    @classmethod
    def extract_endpoints(cls, js_content: str, base_url: str, scope_gate: ScopeGate) -> Set[str]:
        """Extracts and normalizes candidate endpoints from JavaScript content.
        
        Returns:
            Set of validated in-scope normalized URLs.
        """
        candidates: Set[str] = set()
        if not js_content or not isinstance(js_content, str):
            return candidates

        for pattern in cls.ENDPOINT_PATTERNS:
            for match in pattern.findall(js_content):
                endpoint_str = match.strip()

                # Filter out obvious false positives (e.g. file extensions or common static words)
                if endpoint_str.endswith((".png", ".jpg", ".svg", ".css", ".ico", ".woff", ".ttf")):
                    continue
                if len(endpoint_str) < 2 or " " in endpoint_str:
                    continue

                normalized = URLNormalizer.normalize_url(endpoint_str, base_url)
                if normalized and scope_gate.validate_url_in_scope(normalized):
                    candidates.add(normalized)

        return candidates
