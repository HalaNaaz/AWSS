import re
from typing import List
from urllib.parse import urlparse

from backend.app.scanner.passive.base import BasePassiveAnalyzer
from backend.app.scanner.passive.models import HTTPResponseContext, PassiveFinding
from shared.schemas.common import Severity, FindingStatus


class CacheControlAnalyzer(BasePassiveAnalyzer):
    """Passive analyzer for HTTP response caching policies on sensitive endpoints."""

    analyzer_id = "SEC-CACHE-ANALYZER"
    analyzer_name = "HTTP Cache-Control & Sensitive Caching Analyzer"
    category = "Cache Security"
    supported_rules = [
        "PASSIVE-CACHE-SENSITIVE-NO-STORE",
        "PASSIVE-CACHE-SHARED-PUBLIC",
        "PASSIVE-CACHE-PRAGMA-MISSING",
    ]

    SENSITIVE_PATH_PATTERN = re.compile(
        r"/(?:api|auth|login|signin|account|profile|user|users|admin|token|session|checkout|billing|settings)",
        re.IGNORECASE,
    )

    def analyze(self, context: HTTPResponseContext) -> List[PassiveFinding]:
        findings: List[PassiveFinding] = []
        if context.status_code >= 400:
            return findings

        parsed = urlparse(context.url)
        is_sensitive_path = bool(self.SENSITIVE_PATH_PATTERN.search(parsed.path or ""))
        has_set_cookie = bool(context.get_all_header_values("set-cookie"))
        has_auth_req = bool(
            context.request_headers
            and any(k.lower() in {"authorization", "cookie"} for k in context.request_headers)
        )
        is_sensitive = is_sensitive_path or has_set_cookie or has_auth_req
        if not is_sensitive:
            return findings

        cache_control = (context.get_header("cache-control") or "").lower()
        pragma = (context.get_header("pragma") or "").lower()

        if "public" in cache_control and (has_set_cookie or has_auth_req or is_sensitive_path):
            f = PassiveFinding(
                rule_id="PASSIVE-CACHE-SHARED-PUBLIC",
                title="Sensitive or Authenticated Response Explicitly Marked Cacheable (public)",
                description=(
                    f"The response for '{context.url}' includes 'Cache-Control: public' on a sensitive or authenticated "
                    f"context, allowing shared proxies or CDNs to cache potentially private data."
                ),
                cwe_id="CWE-524",
                owasp_category="A05:2021 - Security Misconfiguration",
                severity=Severity.MEDIUM,
                cvss_score=5.3,
                status=FindingStatus.DETECTED,
                confidence=0.90,
                url=context.url,
                evidence_response=f"Cache-Control: {context.get_header('cache-control')}",
                remediation="Set 'Cache-Control: no-store, no-cache, must-revalidate, private' on authenticated or sensitive responses.",
            )
            f.seal_evidence()
            findings.append(f)

        if "no-store" not in cache_control:
            f = PassiveFinding(
                rule_id="PASSIVE-CACHE-SENSITIVE-NO-STORE",
                title="Sensitive Endpoint Missing 'Cache-Control: no-store'",
                description=(
                    f"Sensitive endpoint '{context.url}' does not specify 'no-store' in its Cache-Control header, "
                    f"permitting browsers or intermediate caches to retain sensitive response payloads."
                ),
                cwe_id="CWE-525",
                owasp_category="A05:2021 - Security Misconfiguration",
                severity=Severity.LOW,
                cvss_score=3.7,
                status=FindingStatus.DETECTED,
                confidence=0.85,
                url=context.url,
                evidence_response=f"Cache-Control: {context.get_header('cache-control') or '<missing>'}",
                remediation="Add 'Cache-Control: no-store' (and 'Pragma: no-cache' for HTTP/1.0 compatibility) to sensitive responses.",
            )
            f.seal_evidence()
            findings.append(f)

        if not cache_control and "no-cache" not in pragma:
            f = PassiveFinding(
                rule_id="PASSIVE-CACHE-PRAGMA-MISSING",
                title="Missing Cache-Control and Pragma Directives on Sensitive Response",
                description=(
                    f"Sensitive endpoint '{context.url}' omits both Cache-Control and Pragma headers, "
                    f"leaving caching behavior to client and proxy heuristics."
                ),
                cwe_id="CWE-525",
                owasp_category="A05:2021 - Security Misconfiguration",
                severity=Severity.INFORMATIONAL,
                cvss_score=2.6,
                status=FindingStatus.DETECTED,
                confidence=0.85,
                url=context.url,
                evidence_response="Cache-Control: <missing>\nPragma: <missing>",
                remediation="Explicitly configure 'Cache-Control: no-store, no-cache' and 'Pragma: no-cache'.",
            )
            f.seal_evidence()
            findings.append(f)

        return findings
