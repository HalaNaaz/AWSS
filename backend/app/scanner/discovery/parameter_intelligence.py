import re
from typing import Dict, List, Optional, Set, Tuple, Any
from urllib.parse import urlparse, parse_qsl

from shared.schemas.discovery import (
    ParameterCategory,
    ParameterLocation,
    ParameterIntelligenceSchema
)


class ParameterIntelligenceEngine:
    """Heuristic parameter intelligence and risk classification engine.
    
    Extracts parameters across URLs, forms, and requests, classifies them by security semantics,
    generates contextual risk signals, and enforces privacy-safe value redaction.
    """

    # Keyword mappings for heuristic classification
    CLASSIFICATION_RULES = {
        ParameterCategory.AUTH: {
            "keywords": {"token", "auth", "password", "pass", "passwd", "pwd", "secret", "api_key", "apikey",
                         "access_token", "refresh_token", "credential", "signature", "key", "bearer"},
            "patterns": [re.compile(r"auth|pass(word|wd)?|secret|token|api_?key", re.IGNORECASE)],
            "risk_signal": "Authentication credential or token parameter"
        },
        ParameterCategory.SESSION: {
            "keywords": {"session", "session_id", "sessionid", "sess", "sid", "jsessionid", "phpsessid",
                         "connect.sid", "jwt", "xsrf", "csrf", "csrftoken"},
            "patterns": [re.compile(r"sess(ion)?(_?id)?|sid|jwt|xsrf|csrf", re.IGNORECASE)],
            "risk_signal": "Session identifier or anti-CSRF token"
        },
        ParameterCategory.REDIRECT: {
            "keywords": {"redirect", "redirect_to", "redirect_url", "url", "return", "return_to", "return_url",
                         "goto", "next", "target", "r", "dest", "destination", "out", "view", "link", "forward"},
            "patterns": [re.compile(r"redirect|return(_?to)?|goto|next|target|dest(ination)?", re.IGNORECASE)],
            "risk_signal": "Potential Open Redirect or SSRF candidate"
        },
        ParameterCategory.FILE: {
            "keywords": {"file", "path", "filename", "filepath", "doc", "document", "folder", "include",
                         "template", "dir", "load", "page_file", "attachment", "upload", "download"},
            "patterns": [re.compile(r"file(_?name|_?path)?|path|doc(ument)?|template|include|attach", re.IGNORECASE)],
            "risk_signal": "Potential Path Traversal or LFI/RFI candidate"
        },
        ParameterCategory.SEARCH: {
            "keywords": {"q", "query", "search", "keyword", "term", "find", "filter", "text", "s"},
            "patterns": [re.compile(r"^(q|query|search|filter|term)$", re.IGNORECASE)],
            "risk_signal": "Reflected search query (potential XSS / SQLi candidate)"
        },
        ParameterCategory.PAGINATION: {
            "keywords": {"page", "p", "limit", "offset", "size", "per_page", "page_size", "start",
                         "num", "count", "cursor"},
            "patterns": [re.compile(r"^(page|offset|limit|per_page|start|cursor)$", re.IGNORECASE)],
            "risk_signal": "Pagination / limit control parameter"
        },
        ParameterCategory.IDENTIFIER: {
            "keywords": {"id", "user_id", "userid", "account_id", "uuid", "item_id", "product_id",
                         "order_id", "uid", "pk", "guid"},
            "patterns": [re.compile(r"(_?id|uid|uuid|pk)$", re.IGNORECASE)],
            "risk_signal": "Object identifier (potential IDOR / BOLA candidate)"
        },
        ParameterCategory.URL: {
            "keywords": {"src", "href", "source", "host", "domain", "site", "callback", "webhook", "feed"},
            "patterns": [re.compile(r"^(src|href|callback|webhook|host|domain)$", re.IGNORECASE)],
            "risk_signal": "Resource locator / webhook (potential SSRF candidate)"
        },
        ParameterCategory.SENSITIVE: {
            "keywords": {"ssn", "social_security", "credit_card", "cc", "cvv", "pin", "email",
                         "phone", "mobile", "dob", "birthdate", "address"},
            "patterns": [re.compile(r"ssn|credit_?card|cvv|pin|email|phone|dob", re.IGNORECASE)],
            "risk_signal": "Personally Identifiable Information (PII) or sensitive parameter"
        }
    }

    def __init__(self):
        # Map: (name, location) -> ParameterIntelligenceSchema
        self._parameters: Dict[Tuple[str, ParameterLocation], ParameterIntelligenceSchema] = {}

    @classmethod
    def classify_parameter(cls, name: str) -> Tuple[ParameterCategory, float, List[str]]:
        """Classifies a parameter name into a semantic category with confidence score and risk signals."""
        name_lower = name.lower().strip()
        signals: List[str] = []

        for category, rules in cls.CLASSIFICATION_RULES.items():
            if name_lower in rules["keywords"]:
                signals.append(rules["risk_signal"])
                return category, 0.95, signals
            for pattern in rules["patterns"]:
                if pattern.search(name_lower):
                    signals.append(rules["risk_signal"])
                    return category, 0.80, signals

        return ParameterCategory.UNKNOWN, 0.50, ["Unclassified parameter"]

    @classmethod
    def sanitize_value(cls, category: ParameterCategory, value: Optional[str]) -> str:
        """Sanitizes sample parameter values to prevent secret leaks or PII persistence."""
        if value is None:
            return ""
        str_val = str(value).strip()
        if not str_val:
            return ""

        # Strictly redact sensitive, auth, and session categories
        if category in (ParameterCategory.AUTH, ParameterCategory.SESSION, ParameterCategory.SENSITIVE):
            return "[REDACTED]"

        # Truncate long values
        if len(str_val) > 40:
            return str_val[:37] + "..."

        return str_val

    def record_parameter(
        self,
        name: str,
        location: ParameterLocation,
        endpoint_url: str,
        sample_value: Optional[str] = None
    ) -> ParameterIntelligenceSchema:
        """Records an observed parameter occurrence and updates intelligence metrics."""
        clean_name = name.strip()
        if not clean_name:
            raise ValueError("Parameter name cannot be empty")

        key = (clean_name, location)
        if key in self._parameters:
            existing = self._parameters[key]
            if endpoint_url not in existing.endpoints_found:
                existing.endpoints_found.append(endpoint_url)
            if sample_value:
                sanitized = self.sanitize_value(existing.category, sample_value)
                if sanitized and sanitized not in existing.sample_values_redacted and len(existing.sample_values_redacted) < 3:
                    existing.sample_values_redacted.append(sanitized)
            return existing

        category, confidence, risk_signals = self.classify_parameter(clean_name)
        sanitized_samples = []
        if sample_value:
            s_val = self.sanitize_value(category, sample_value)
            if s_val:
                sanitized_samples.append(s_val)

        param = ParameterIntelligenceSchema(
            name=clean_name,
            location=location,
            category=category,
            confidence=confidence,
            endpoints_found=[endpoint_url],
            sample_values_redacted=sanitized_samples,
            risk_signals=risk_signals
        )
        self._parameters[key] = param
        return param

    def extract_from_url(self, url: str) -> List[ParameterIntelligenceSchema]:
        """Extracts and records query parameters from a URL."""
        results: List[ParameterIntelligenceSchema] = []
        parsed = urlparse(url)
        if not parsed.query:
            return results

        for key, val in parse_qsl(parsed.query, keep_blank_values=True):
            param = self.record_parameter(
                name=key,
                location=ParameterLocation.QUERY,
                endpoint_url=url,
                sample_value=val
            )
            results.append(param)
        return results

    def extract_from_form_fields(self, fields: List[Dict[str, Any]], form_action: str) -> List[ParameterIntelligenceSchema]:
        """Extracts and records parameters from HTML form field definitions."""
        results: List[ParameterIntelligenceSchema] = []
        for field in fields:
            name = field.get("name")
            if not name:
                continue
            default_val = field.get("default_value")
            param = self.record_parameter(
                name=name,
                location=ParameterLocation.BODY,
                endpoint_url=form_action,
                sample_value=default_val
            )
            results.append(param)
        return results

    def get_parameters(self) -> List[ParameterIntelligenceSchema]:
        """Returns all discovered parameters."""
        return list(self._parameters.values())

    def get_by_category(self, category: ParameterCategory) -> List[ParameterIntelligenceSchema]:
        """Filters parameters by classification category."""
        return [p for p in self._parameters.values() if p.category == category]
