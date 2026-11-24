from typing import List
from urllib.parse import urlparse

from backend.app.scanner.passive.base import BasePassiveAnalyzer
from backend.app.scanner.passive.models import HTTPResponseContext, PassiveFinding
from shared.schemas.common import Severity, FindingStatus


class CORSAnalyzer(BasePassiveAnalyzer):
    """Passive analyzer for Cross-Origin Resource Sharing (CORS) misconfigurations."""

    analyzer_id = "CORS-SEC-ANALYZER"
    analyzer_name = "CORS Policy Configuration Analyzer"
    category = "CORS Configuration"
    supported_rules = [
        "PASSIVE-CORS-WILDCARD-WITH-CREDENTIALS",
        "PASSIVE-CORS-REFLECTED-ORIGIN-WITH-CREDENTIALS",
        "PASSIVE-CORS-WILDCARD-ORIGIN",
        "PASSIVE-CORS-NULL-ORIGIN",
        "PASSIVE-CORS-OVERLY-PERMISSIVE-METHODS"
    ]

    def analyze(self, context: HTTPResponseContext) -> List[PassiveFinding]:
        findings: List[PassiveFinding] = []

        acao = context.get_header("access-control-allow-origin")
        acac = context.get_header("access-control-allow-credentials")
        acam = context.get_header("access-control-allow-methods")

        if not acao:
            return findings

        acao_clean = acao.strip()
        acac_bool = acac is not None and acac.strip().lower() == "true"

        # 1. Wildcard Origin with Credentials Allowed (Severe Misconfiguration)
        if (acao_clean == "*" or acao_clean.lower() == "null") and acac_bool:
            f = PassiveFinding(
                rule_id="PASSIVE-CORS-WILDCARD-WITH-CREDENTIALS",
                title="CORS Policy Combines Wildcard/Null Origin with Credentials Allowed",
                description="The server returns Access-Control-Allow-Origin: * (or null) alongside Access-Control-Allow-Credentials: true, allowing malicious third-party origins to extract authenticated user data.",
                cwe_id="CWE-942",
                owasp_category="A01:2021 - Broken Access Control",
                severity=Severity.HIGH,
                cvss_score=8.1,
                status=FindingStatus.DETECTED,
                confidence=0.95,
                url=context.url,
                evidence_response=f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                remediation="Specify explicit, trusted origins in Access-Control-Allow-Origin rather than using wildcard or null when credentials are enabled."
            )
            f.seal_evidence()
            findings.append(f)

        # 1B. Dynamically Reflected Origin with Credentials Allowed
        elif acac_bool and context.request_headers:
            req_origin = context.request_headers.get("Origin") or context.request_headers.get("origin")
            if req_origin and req_origin.lower() == acao_clean.lower() and req_origin != "null":
                # Check if origin is unconstrained/external
                f = PassiveFinding(
                    rule_id="PASSIVE-CORS-REFLECTED-ORIGIN-WITH-CREDENTIALS",
                    title="CORS Reflects Arbitrary Request Origin with Credentials Allowed",
                    description="The server dynamically mirrors the inbound Origin header in Access-Control-Allow-Origin while setting Access-Control-Allow-Credentials: true, allowing arbitrary cross-origin sites to execute authenticated requests.",
                    cwe_id="CWE-942",
                    owasp_category="A01:2021 - Broken Access Control",
                    severity=Severity.HIGH,
                    cvss_score=8.5,
                    status=FindingStatus.DETECTED,
                    confidence=0.95,
                    url=context.url,
                    evidence_response=f"Request Origin: {req_origin}\nAccess-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                    remediation="Validate request origins against an explicit strict allowlist of authorized domains before echoing the origin."
                )
                f.seal_evidence()
                findings.append(f)

        # 2. Origin set to null
        elif acao_clean.lower() == "null":
            f = PassiveFinding(
                rule_id="PASSIVE-CORS-NULL-ORIGIN",
                title="CORS Allows 'null' Origin",
                description="The CORS header allows the 'null' origin. Sandboxed iframes, local file schemes, and data URIs can send requests with an Origin header of null, bypassing cross-origin restrictions.",
                cwe_id="CWE-942",
                owasp_category="A01:2021 - Broken Access Control",
                severity=Severity.MEDIUM,
                cvss_score=5.3,
                status=FindingStatus.DETECTED,
                confidence=0.9,
                url=context.url,
                evidence_response=f"Access-Control-Allow-Origin: {acao}",
                remediation="Do not allow the 'null' origin in Access-Control-Allow-Origin headers."
            )
            f.seal_evidence()
            findings.append(f)

        # 3. Wildcard origin on API / JSON endpoints
        elif acao_clean == "*":
            content_type = (context.get_header("content-type") or "").lower()
            is_api = "application/json" in content_type or "/api/" in context.url.lower()

            if is_api:
                f = PassiveFinding(
                    rule_id="PASSIVE-CORS-WILDCARD-ORIGIN",
                    title="API Endpoint Exposes Permissive Wildcard CORS Policy (Access-Control-Allow-Origin: *)",
                    description="The API endpoint exposes Access-Control-Allow-Origin: *, allowing any public web page to read response data via client-side cross-origin fetch requests.",
                    cwe_id="CWE-942",
                    owasp_category="A01:2021 - Broken Access Control",
                    severity=Severity.LOW,
                    cvss_score=3.7,
                    status=FindingStatus.DETECTED,
                    confidence=0.85,
                    url=context.url,
                    evidence_response=f"Access-Control-Allow-Origin: {acao}\nContent-Type: {content_type}",
                    remediation="If this API is private or authenticated, restrict Access-Control-Allow-Origin to authorized corporate domains."
                )
                f.seal_evidence()
                findings.append(f)

        # 4. Overly permissive HTTP methods allowed
        if acam and "*" in acam:
            f = PassiveFinding(
                rule_id="PASSIVE-CORS-OVERLY-PERMISSIVE-METHODS",
                title="CORS Allows All HTTP Methods via Wildcard (*)",
                description=f"The Access-Control-Allow-Methods header uses wildcard '*', permitting arbitrary HTTP methods across origin boundaries.",
                cwe_id="CWE-942",
                owasp_category="A01:2021 - Broken Access Control",
                severity=Severity.LOW,
                cvss_score=3.1,
                status=FindingStatus.DETECTED,
                confidence=0.9,
                url=context.url,
                evidence_response=f"Access-Control-Allow-Methods: {acam}",
                remediation="Explicitly enumerate required safe HTTP methods (e.g. GET, POST, OPTIONS) in Access-Control-Allow-Methods."
            )
            f.seal_evidence()
            findings.append(f)

        return findings
