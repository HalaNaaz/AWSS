import re
import urllib.parse
from typing import List, Set
from uuid import UUID

from shared.schemas.common import Severity, FindingStatus
from backend.app.scanner.active.base import BaseActiveAnalyzer
from backend.app.scanner.active.models import ActiveTarget, ActiveFinding, RequestBudgetTracker
from backend.app.scanner.crawler.client import AsyncHTTPClient
from backend.app.scanner.evidence.redactor import EvidenceRedactor


class AuthenticationAnalyzer(BaseActiveAnalyzer):
    """Conservative Authentication & Session Security Analyzer.
    
    Checks:
    - Session identifier exposed in URL query parameters.
    - Authentication surface or login forms accessible over cleartext HTTP.
    - Session fixation indicator (session identifier remains identical across requests).
    
    Safety Guarantee:
    - Strictly avoids password guessing, credential stuffing, brute force, or account takeover.
    """

    AUTH_PATH_PATTERNS = [
        re.compile(r"/(?:login|signin|authenticate|auth|session)", re.I)
    ]

    SESSION_PARAM_PATTERNS = [
        re.compile(r"^(?:jsessionid|phpsessid|aspsessionid|session_id|sid|token|access_token|auth)$", re.I)
    ]

    @property
    def analyzer_id(self) -> str:
        return "ACT-AUTH-ANALYZER"

    @property
    def analyzer_name(self) -> str:
        return "Authentication & Session Security Detector"

    @property
    def category(self) -> str:
        return "Authentication and Session Management"

    @property
    def supported_rules(self) -> List[str]:
        return [
            "ACT-AUTH-SESSION-URL",
            "ACT-AUTH-CLEAR-TEXT-LOGIN",
            "ACT-AUTH-FIXATION",
        ]

    async def check(
        self,
        target: ActiveTarget,
        client: AsyncHTTPClient,
        budget: RequestBudgetTracker,
        scan_id: UUID,
    ) -> List[ActiveFinding]:
        findings: List[ActiveFinding] = []
        parsed = urllib.parse.urlparse(target.url)

        # 1. Session Token in URL Parameter Check
        if target.parameters:
            for param_name, param_val in target.parameters.items():
                if any(p.match(param_name) for p in self.SESSION_PARAM_PATTERNS):
                    findings.append(
                        ActiveFinding(
                            rule_id="ACT-AUTH-SESSION-URL",
                            title=f"Session Identifier Exposed in URL Parameter '{param_name}'",
                            description=(
                                f"The application accepts session or authentication token in URL query parameter '{param_name}'. "
                                f"Exposing session tokens in URLs causes credentials to be logged in server access logs, browser history, "
                                f"and HTTP Referer headers."
                            ),
                            cwe_id="CWE-598",
                            owasp_category="A07:2021 - Identification & Authentication Failures",
                            severity=Severity.MEDIUM,
                            cvss_score=5.3,
                            status=FindingStatus.VERIFIED,
                            confidence=0.95,
                            url=target.url,
                            parameter=param_name,
                            http_method=target.method,
                            evidence_request=f"Target URL: {target.url}",
                            remediation="Transmit session identifiers strictly via HTTP cookies with HttpOnly and Secure flags, never via URL query parameters.",
                            detection_module=self.analyzer_id,
                            probe_count=0,
                        )
                    )

        # 2. Authentication Surface over Cleartext HTTP Check
        is_auth_endpoint = any(pat.search(parsed.path) for pat in self.AUTH_PATH_PATTERNS)
        if is_auth_endpoint and parsed.scheme.lower() == "http":
            findings.append(
                ActiveFinding(
                    rule_id="ACT-AUTH-CLEAR-TEXT-LOGIN",
                    title="Authentication Endpoint Accessible Over Cleartext HTTP",
                    description=(
                        f"Authentication endpoint '{target.url}' is served over unencrypted HTTP. "
                        f"Credentials submitted over unencrypted transport can be intercepted or manipulated in transit."
                    ),
                    cwe_id="CWE-319",
                    owasp_category="A02:2021 - Cryptographic Failures",
                    severity=Severity.HIGH,
                    cvss_score=7.4,
                    status=FindingStatus.VERIFIED,
                    confidence=0.99,
                    url=target.url,
                    http_method=target.method,
                    evidence_response="Scheme: http://",
                    remediation="Enforce HTTPS across the entire application and redirect all HTTP authentication endpoints to HTTPS.",
                    detection_module=self.analyzer_id,
                    probe_count=0,
                )
            )

        # 3. Session Fixation Probing Check
        if is_auth_endpoint and budget.can_request():
            # Send initial request to obtain pre-session cookie
            budget.consume(1)
            initial_resp, _ = await client.get(target.url)
            if initial_resp and "set-cookie" in initial_resp.headers:
                raw_cookie = initial_resp.headers["set-cookie"]
                cookie_match = re.search(r"((?:session|sid|token|auth)[^=]*)=([^;]+)", raw_cookie, re.I)
                if cookie_match:
                    cookie_name = cookie_match.group(1)
                    cookie_val = cookie_match.group(2)

                    # Send request with this pre-existing cookie to simulate pre-auth session
                    if budget.can_request():
                        budget.consume(1)
                        second_resp, _ = await client.request(
                            method="GET",
                            url=target.url,
                            headers={"Cookie": f"{cookie_name}={cookie_val}"},
                        )
                        if second_resp:
                            second_cookie_hdr = second_resp.headers.get("set-cookie", "")
                            # If server does not renew the cookie or explicitly confirms the same session
                            if second_cookie_hdr and cookie_val in second_cookie_hdr:
                                findings.append(
                                    ActiveFinding(
                                        rule_id="ACT-AUTH-FIXATION",
                                        title=f"Potential Session Fixation on '{cookie_name}'",
                                        description=(
                                            f"Session cookie '{cookie_name}' was retained without regeneration when accessing "
                                            f"authentication surface '{target.url}'."
                                        ),
                                        cwe_id="CWE-384",
                                        owasp_category="A07:2021 - Identification & Authentication Failures",
                                        severity=Severity.MEDIUM,
                                        cvss_score=6.5,
                                        status=FindingStatus.SUSPECTED,
                                        confidence=0.70,
                                        url=target.url,
                                        parameter=cookie_name,
                                        http_method="GET",
                                        evidence_request=EvidenceRedactor.redact(f"Cookie: {cookie_name}={cookie_val}"),
                                        evidence_response=EvidenceRedactor.redact(f"Set-Cookie: {second_cookie_hdr[:200]}"),
                                        remediation="Always invalidate the existing session and generate a brand new session identifier upon authentication state change.",
                                        detection_module=self.analyzer_id,
                                        probe_count=2,
                                    )
                                )

        return findings
