import re
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

from backend.app.scanner.passive.base import BasePassiveAnalyzer
from backend.app.scanner.passive.models import HTTPResponseContext, PassiveFinding
from shared.schemas.common import Severity, FindingStatus


class CookieSecurityAnalyzer(BasePassiveAnalyzer):
    """Passive analyzer for Set-Cookie response security flags and attributes."""

    analyzer_id = "COOKIE-SEC-ANALYZER"
    analyzer_name = "Cookie Security Flag Analyzer"
    category = "Cookie Security"
    supported_rules = [
        "PASSIVE-COOKIE-SECURE-MISSING",
        "PASSIVE-COOKIE-HTTPONLY-MISSING",
        "PASSIVE-COOKIE-SAMESITE-MISSING",
        "PASSIVE-COOKIE-SAMESITE-NONE-INSECURE",
        "PASSIVE-COOKIE-EXCESSIVE-MAXAGE",
        "PASSIVE-COOKIE-PLAINTEXT-TRANSMISSION"
    ]

    SENSITIVE_COOKIE_PATTERN = re.compile(
        r'(?i)(session|sess|token|jwt|auth|sid|phpsessid|jsessionid|asp\.net_sessionid|connect\.sid|key|secret|id)'
    )

    def _parse_cookie(self, raw_cookie: str) -> Dict[str, Any]:
        """Parses a Set-Cookie header into its name, value, and attributes."""
        parts = [p.strip() for p in raw_cookie.split(";")]
        if not parts or not parts[0]:
            return {}

        name_val = parts[0].split("=", 1)
        name = name_val[0].strip()
        val = name_val[1].strip() if len(name_val) > 1 else ""

        attrs: Dict[str, Any] = {
            "name": name,
            "value": val,
            "secure": False,
            "httponly": False,
            "samesite": None,
            "max_age": None,
            "expires": None,
            "domain": None,
            "path": None,
            "raw": raw_cookie
        }

        for p in parts[1:]:
            p_lower = p.lower()
            if p_lower == "secure":
                attrs["secure"] = True
            elif p_lower == "httponly":
                attrs["httponly"] = True
            elif p_lower.startswith("samesite="):
                attrs["samesite"] = p.split("=", 1)[1].strip().lower()
            elif p_lower.startswith("max-age="):
                try:
                    attrs["max_age"] = int(p.split("=", 1)[1].strip())
                except ValueError:
                    pass
            elif p_lower.startswith("expires="):
                attrs["expires"] = p.split("=", 1)[1].strip()
            elif p_lower.startswith("domain="):
                attrs["domain"] = p.split("=", 1)[1].strip()
            elif p_lower.startswith("path="):
                attrs["path"] = p.split("=", 1)[1].strip()

        return attrs

    def analyze(self, context: HTTPResponseContext) -> List[PassiveFinding]:
        findings: List[PassiveFinding] = []
        parsed_url = urlparse(context.url)
        is_https = parsed_url.scheme.lower() == "https"

        raw_cookie_headers = context.get_all_header_values("set-cookie")
        if not raw_cookie_headers:
            return findings

        # Process each individual Set-Cookie directive
        for raw_cookie in raw_cookie_headers:
            cookie = self._parse_cookie(raw_cookie)
            if not cookie or not cookie.get("name"):
                continue

            cookie_name = cookie["name"]
            is_sensitive = bool(self.SENSITIVE_COOKIE_PATTERN.search(cookie_name))

            # 1. Plaintext HTTP cookie transmission
            if not is_https:
                f = PassiveFinding(
                    rule_id="PASSIVE-COOKIE-PLAINTEXT-TRANSMISSION",
                    title=f"Cookie '{cookie_name}' Set Over Unencrypted HTTP Connection",
                    description=f"The cookie '{cookie_name}' was transmitted over an unencrypted cleartext HTTP channel, exposing it to passive network eavesdropping.",
                    cwe_id="CWE-319",
                    owasp_category="A02:2021 - Cryptographic Failures",
                    severity=Severity.HIGH if is_sensitive else Severity.MEDIUM,
                    cvss_score=7.4 if is_sensitive else 5.3,
                    status=FindingStatus.DETECTED,
                    confidence=0.95,
                    url=context.url,
                    parameter=cookie_name,
                    evidence_response=f"Set-Cookie: {raw_cookie}",
                    remediation="Serve application strictly over HTTPS and ensure all cookies are marked with the 'Secure' attribute."
                )
                f.seal_evidence()
                findings.append(f)

            # 2. Missing Secure Flag (when served over HTTPS)
            if is_https and not cookie["secure"]:
                f = PassiveFinding(
                    rule_id="PASSIVE-COOKIE-SECURE-MISSING",
                    title=f"Cookie '{cookie_name}' Missing 'Secure' Attribute",
                    description=f"The cookie '{cookie_name}' lacks the 'Secure' attribute, allowing browsers to send it over cleartext HTTP if a user requests an insecure URL.",
                    cwe_id="CWE-614",
                    owasp_category="A05:2021 - Security Misconfiguration",
                    severity=Severity.MEDIUM if is_sensitive else Severity.LOW,
                    cvss_score=5.3 if is_sensitive else 3.5,
                    status=FindingStatus.DETECTED,
                    confidence=0.95,
                    url=context.url,
                    parameter=cookie_name,
                    evidence_response=f"Set-Cookie: {raw_cookie}",
                    remediation=f"Append '; Secure' to the Set-Cookie definition for '{cookie_name}'."
                )
                f.seal_evidence()
                findings.append(f)

            # 3. Missing HttpOnly Flag on Sensitive Cookies
            if is_sensitive and not cookie["httponly"]:
                f = PassiveFinding(
                    rule_id="PASSIVE-COOKIE-HTTPONLY-MISSING",
                    title=f"Sensitive Session/Auth Cookie '{cookie_name}' Missing 'HttpOnly' Attribute",
                    description=f"The cookie '{cookie_name}' appears to carry session or authentication tokens but is not protected by 'HttpOnly', allowing client-side scripts to read it via document.cookie.",
                    cwe_id="CWE-1004",
                    owasp_category="A05:2021 - Security Misconfiguration",
                    severity=Severity.MEDIUM,
                    cvss_score=5.8,
                    status=FindingStatus.DETECTED,
                    confidence=0.9,
                    url=context.url,
                    parameter=cookie_name,
                    evidence_response=f"Set-Cookie: {raw_cookie}",
                    remediation=f"Append '; HttpOnly' to the Set-Cookie definition for '{cookie_name}'."
                )
                f.seal_evidence()
                findings.append(f)

            # 4. SameSite Attribute Check
            if not cookie["samesite"]:
                f = PassiveFinding(
                    rule_id="PASSIVE-COOKIE-SAMESITE-MISSING",
                    title=f"Cookie '{cookie_name}' Missing 'SameSite' Attribute",
                    description=f"The cookie '{cookie_name}' does not declare a SameSite attribute, which may allow cross-site requests to transmit it and increase exposure to Cross-Site Request Forgery (CSRF).",
                    cwe_id="CWE-1275",
                    owasp_category="A01:2021 - Broken Access Control",
                    severity=Severity.LOW,
                    cvss_score=3.7,
                    status=FindingStatus.DETECTED,
                    confidence=0.9,
                    url=context.url,
                    parameter=cookie_name,
                    evidence_response=f"Set-Cookie: {raw_cookie}",
                    remediation=f"Configure '{cookie_name}' with 'SameSite=Lax' or 'SameSite=Strict'."
                )
                f.seal_evidence()
                findings.append(f)
            elif cookie["samesite"] == "none" and not cookie["secure"]:
                f = PassiveFinding(
                    rule_id="PASSIVE-COOKIE-SAMESITE-NONE-INSECURE",
                    title=f"Cookie '{cookie_name}' Configured with SameSite=None Without Secure Attribute",
                    description=f"The cookie '{cookie_name}' specifies SameSite=None without the Secure attribute, which modern browsers reject and which violates modern cookie isolation policies.",
                    cwe_id="CWE-1275",
                    owasp_category="A05:2021 - Security Misconfiguration",
                    severity=Severity.MEDIUM,
                    cvss_score=4.5,
                    status=FindingStatus.DETECTED,
                    confidence=0.95,
                    url=context.url,
                    parameter=cookie_name,
                    evidence_response=f"Set-Cookie: {raw_cookie}",
                    remediation=f"When using SameSite=None, ensure the 'Secure' attribute is also set."
                )
                f.seal_evidence()
                findings.append(f)

            # 5. Excessive Expiration Duration on Session Cookie
            if is_sensitive and cookie.get("max_age") is not None:
                one_year_seconds = 31536000
                if cookie["max_age"] > one_year_seconds:
                    f = PassiveFinding(
                        rule_id="PASSIVE-COOKIE-EXCESSIVE-MAXAGE",
                        title=f"Sensitive Cookie '{cookie_name}' Has Excessively Long Expiration Duration",
                        description=f"The session/auth cookie '{cookie_name}' has a max-age of {cookie['max_age']} seconds (exceeding 1 year), increasing the window for session hijacking.",
                        cwe_id="CWE-613",
                        owasp_category="A07:2021 - Identification and Authentication Failures",
                        severity=Severity.LOW,
                        cvss_score=3.2,
                        status=FindingStatus.DETECTED,
                        confidence=0.85,
                        url=context.url,
                        parameter=cookie_name,
                        evidence_response=f"Set-Cookie: {raw_cookie}",
                        remediation="Set appropriate session expiration timeouts (e.g., 8-24 hours max-age) for authentication tokens."
                    )
                    f.seal_evidence()
                    findings.append(f)

        return findings
