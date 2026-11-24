import os
import re
from typing import Optional, Dict, Any, List, Tuple
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode, urljoin
from shared.schemas.discovery import EndpointCategory


# File extension to category mapping
EXTENSION_CATEGORIES: Dict[str, EndpointCategory] = {
    ".js": EndpointCategory.JAVASCRIPT,
    ".mjs": EndpointCategory.JAVASCRIPT,
    ".css": EndpointCategory.CSS,
    ".png": EndpointCategory.IMAGE,
    ".jpg": EndpointCategory.IMAGE,
    ".jpeg": EndpointCategory.IMAGE,
    ".gif": EndpointCategory.IMAGE,
    ".svg": EndpointCategory.IMAGE,
    ".webp": EndpointCategory.IMAGE,
    ".ico": EndpointCategory.IMAGE,
    ".bmp": EndpointCategory.IMAGE,
    ".tiff": EndpointCategory.IMAGE,
    ".pdf": EndpointCategory.DOCUMENT,
    ".doc": EndpointCategory.DOCUMENT,
    ".docx": EndpointCategory.DOCUMENT,
    ".xls": EndpointCategory.DOCUMENT,
    ".xlsx": EndpointCategory.DOCUMENT,
    ".ppt": EndpointCategory.DOCUMENT,
    ".pptx": EndpointCategory.DOCUMENT,
    ".zip": EndpointCategory.DOCUMENT,
    ".tar": EndpointCategory.DOCUMENT,
    ".gz": EndpointCategory.DOCUMENT,
}

# Common destructive paths that must never be crawled
EXCLUDED_PATH_PATTERNS = [
    re.compile(r"/(?:logout|signout|log-off|sign-off)(?:[/?#]|$)", re.IGNORECASE),
    re.compile(r"/(?:delete|destroy|remove|purge)(?:[/?#]|$)", re.IGNORECASE),
    re.compile(r"/(?:reset-password|forgot-password)(?:[/?#]|$)", re.IGNORECASE),
]


class URLNormalizer:
    """Deterministic URL normalizer and canonicalization engine."""

    ALLOWED_SCHEMES = {"http", "https"}

    @classmethod
    def is_valid_url(cls, url: str) -> bool:
        """Validates that a URL has a valid permitted scheme and non-empty hostname."""
        if not url or not isinstance(url, str):
            return False
        try:
            parsed = urlparse(url)
            return (
                parsed.scheme.lower() in cls.ALLOWED_SCHEMES
                and bool(parsed.netloc)
                and not parsed.netloc.startswith(".")
            )
        except Exception:
            return False

    @classmethod
    def is_destructive_url(cls, url: str) -> bool:
        """Identifies potentially state-destroying endpoints that must not be crawled."""
        path = urlparse(url).path
        for pattern in EXCLUDED_PATH_PATTERNS:
            if pattern.search(path):
                return True
        return False

    @classmethod
    def normalize_url(cls, raw_url: str, base_url: Optional[str] = None) -> Optional[str]:
        """Resolves relative URLs, removes fragments, normalizes host/port, and deterministically sorts query params."""
        if not raw_url or not isinstance(raw_url, str):
            return None

        # Clean whitespace and control chars
        cleaned = raw_url.strip()

        # Reject javascript:, mailto:, data:, tel: schemes immediately
        if re.match(r"^(?:javascript|mailto|data|tel|sms|ftp):", cleaned, re.IGNORECASE):
            return None

        # Resolve relative URL against base_url if provided
        if base_url:
            try:
                cleaned = urljoin(base_url, cleaned)
            except Exception:
                return None

        if not cls.is_valid_url(cleaned):
            return None

        try:
            parsed = urlparse(cleaned)

            scheme = parsed.scheme.lower()
            if scheme not in cls.ALLOWED_SCHEMES:
                return None

            # Normalize hostname to lowercase
            netloc = parsed.netloc.lower()

            # Remove default ports
            if scheme == "http" and netloc.endswith(":80"):
                netloc = netloc[:-3]
            elif scheme == "https" and netloc.endswith(":443"):
                netloc = netloc[:-4]

            # Normalize path: collapse duplicate slashes while preserving root slash
            path = parsed.path or "/"
            path = re.sub(r"/{2,}", "/", path)

            # Deterministically sort query parameters
            query = ""
            if parsed.query:
                params = parse_qsl(parsed.query, keep_blank_values=True)
                sorted_params = sorted(params, key=lambda x: (x[0], x[1]))
                query = urlencode(sorted_params)

            # Reconstruct URL without fragment
            normalized = urlunparse((scheme, netloc, path, "", query, ""))
            return normalized

        except Exception:
            return None

    @classmethod
    def extract_query_params(cls, url: str) -> Dict[str, List[str]]:
        """Extracts parsed query parameter dictionary from URL."""
        try:
            parsed = urlparse(url)
            params: Dict[str, List[str]] = {}
            for k, v in parse_qsl(parsed.query, keep_blank_values=True):
                params.setdefault(k, []).append(v)
            return params
        except Exception:
            return {}

    @classmethod
    def classify_endpoint(cls, url: str, content_type: Optional[str] = None) -> EndpointCategory:
        """Classifies a URL into an EndpointCategory based on content-type header and path extension."""
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
            if "application/pdf" in ct:
                return EndpointCategory.DOCUMENT
            if "text/html" in ct:
                return EndpointCategory.PAGE

        path = urlparse(url).path.lower()

        # Check file extension
        _, ext = os.path.splitext(path)
        if ext in EXTENSION_CATEGORIES:
            return EXTENSION_CATEGORIES[ext]

        # Check common API route prefixes
        if re.search(r"/(?:api|v\d+|graphql|rest)(?:/|$)", path):
            return EndpointCategory.API

        # Default web document/page
        return EndpointCategory.PAGE
