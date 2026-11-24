import re
from typing import List, Optional
from urllib.parse import urlparse

from backend.app.scanner.passive.base import BasePassiveAnalyzer
from backend.app.scanner.passive.models import HTTPResponseContext, PassiveFinding
from shared.schemas.common import Severity, FindingStatus


class SecurityHeaderAnalyzer(BasePassiveAnalyzer):
    """Passive analyzer for HTTP response security headers."""

    analyzer_id = "SEC-HDR-ANALYZER"
    analyzer_name = "Security Header Policy Analyzer"
    category = "Security Headers"
    supported_rules = [
        "PASSIVE-HDR-CSP-MISSING",
        "PASSIVE-HDR-CSP-UNSAFE",
        "PASSIVE-HDR-CSP-NO-DEFAULT",
        "PASSIVE-HDR-CSP-WILDCARD",
        "PASSIVE-HDR-HSTS-MISSING",
        "PASSIVE-HDR-HSTS-SHORT-MAXAGE",
        "PASSIVE-HDR-HSTS-NO-SUBDOMAINS",
        "PASSIVE-HDR-HSTS-NO-PRELOAD",
        "PASSIVE-HDR-XCTO-MISSING",
        "PASSIVE-HDR-XFO-MISSING",
        "PASSIVE-HDR-XFO-DEPRECATED",
        "PASSIVE-HDR-REFERRER-MISSING",
        "PASSIVE-HDR-REFERRER-UNSAFE",
        "PASSIVE-HDR-PERMISSIONS-MISSING",
        "PASSIVE-HDR-PERMISSIONS-PERMISSIVE"
    ]

    def analyze(self, context: HTTPResponseContext) -> List[PassiveFinding]:
        findings: List[PassiveFinding] = []
        parsed_url = urlparse(context.url)
        is_https = parsed_url.scheme.lower() == "https"
        is_html = "text/html" in (context.get_header("content-type") or "").lower()

        # 1. Content-Security-Policy (CSP)
        csp = context.get_header("content-security-policy")
        if not csp:
            if is_html:
                f = PassiveFinding(
                    rule_id="PASSIVE-HDR-CSP-MISSING",
                    title="Missing Content-Security-Policy (CSP)",
                    description="The HTTP response does not include a Content-Security-Policy header, leaving the application vulnerable to Cross-Site Scripting (XSS) and code injection.",
                    cwe_id="CWE-693",
                    owasp_category="A05:2021 - Security Misconfiguration",
                    severity=Severity.MEDIUM,
                    cvss_score=5.4,
                    status=FindingStatus.DETECTED,
                    confidence=0.95,
                    url=context.url,
                    evidence_response="[Headers Observed]\n" + "\n".join(f"{k}: {v}" for k, v in context.headers.items()),
                    remediation="Implement a strict Content-Security-Policy header specifying trusted script sources (e.g., default-src 'self'; script-src 'self')."
                )
                f.seal_evidence()
                findings.append(f)
        else:
            csp_lower = csp.lower()
            if "'unsafe-inline'" in csp_lower or "'unsafe-eval'" in csp_lower:
                f = PassiveFinding(
                    rule_id="PASSIVE-HDR-CSP-UNSAFE",
                    title="Insecure Content-Security-Policy Directives ('unsafe-inline' / 'unsafe-eval')",
                    description="The Content-Security-Policy header permits 'unsafe-inline' or 'unsafe-eval', significantly weakening protection against script injection.",
                    cwe_id="CWE-693",
                    owasp_category="A05:2021 - Security Misconfiguration",
                    severity=Severity.MEDIUM,
                    cvss_score=5.0,
                    status=FindingStatus.DETECTED,
                    confidence=0.9,
                    url=context.url,
                    evidence_response=f"Content-Security-Policy: {csp}",
                    remediation="Refactor inline scripts to external files and use nonces or cryptographic hashes instead of 'unsafe-inline' and 'unsafe-eval'."
                )
                f.seal_evidence()
                findings.append(f)

            if "default-src" not in csp_lower:
                f = PassiveFinding(
                    rule_id="PASSIVE-HDR-CSP-NO-DEFAULT",
                    title="Content-Security-Policy Missing default-src Fallback Directive",
                    description="The CSP header does not declare a default-src directive, potentially permitting unconstrained resource loading for unspecified types.",
                    cwe_id="CWE-693",
                    owasp_category="A05:2021 - Security Misconfiguration",
                    severity=Severity.LOW,
                    cvss_score=3.7,
                    status=FindingStatus.DETECTED,
                    confidence=0.9,
                    url=context.url,
                    evidence_response=f"Content-Security-Policy: {csp}",
                    remediation="Add a restrictive default-src directive (e.g. default-src 'none' or default-src 'self')."
                )
                f.seal_evidence()
                findings.append(f)

            if re.search(r'(?:script-src|default-src)\s+[^;]*\*(?!\.)', csp_lower):
                f = PassiveFinding(
                    rule_id="PASSIVE-HDR-CSP-WILDCARD",
                    title="Content-Security-Policy Contains Unrestricted Wildcard Domain (*)",
                    description="The CSP header includes wildcard '*' in script-src or default-src, allowing scripts to be loaded from any origin.",
                    cwe_id="CWE-693",
                    owasp_category="A05:2021 - Security Misconfiguration",
                    severity=Severity.MEDIUM,
                    cvss_score=5.2,
                    status=FindingStatus.DETECTED,
                    confidence=0.9,
                    url=context.url,
                    evidence_response=f"Content-Security-Policy: {csp}",
                    remediation="Replace wildcard source expressions with explicitly trusted origin domains."
                )
                f.seal_evidence()
                findings.append(f)

        # 2. Strict-Transport-Security (HSTS)
        hsts = context.get_header("strict-transport-security")
        if is_https:
            if not hsts:
                f = PassiveFinding(
                    rule_id="PASSIVE-HDR-HSTS-MISSING",
                    title="Missing HTTP Strict-Transport-Security (HSTS) Header",
                    description="The HTTPS endpoint does not transmit an HSTS header, leaving users susceptible to SSL-stripping and man-in-the-middle downgrade attacks.",
                    cwe_id="CWE-319",
                    owasp_category="A02:2021 - Cryptographic Failures",
                    severity=Severity.MEDIUM,
                    cvss_score=5.3,
                    status=FindingStatus.DETECTED,
                    confidence=0.95,
                    url=context.url,
                    evidence_response="Strict-Transport-Security header was not returned in HTTPS response.",
                    remediation="Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload."
                )
                f.seal_evidence()
                findings.append(f)
            else:
                hsts_lower = hsts.lower()
                # Check max-age
                max_age_match = re.search(r'max-age=(\d+)', hsts_lower)
                if max_age_match:
                    max_age_val = int(max_age_match.group(1))
                    if max_age_val < 10368000:  # < 120 days
                        f = PassiveFinding(
                            rule_id="PASSIVE-HDR-HSTS-SHORT-MAXAGE",
                            title="HSTS max-age Directive Is Too Short",
                            description=f"The HSTS max-age duration ({max_age_val} seconds) is less than the recommended 120 days (10,368,000 seconds).",
                            cwe_id="CWE-319",
                            owasp_category="A02:2021 - Cryptographic Failures",
                            severity=Severity.LOW,
                            cvss_score=3.1,
                            status=FindingStatus.DETECTED,
                            confidence=0.9,
                            url=context.url,
                            evidence_response=f"Strict-Transport-Security: {hsts}",
                            remediation="Set HSTS max-age to at least 31536000 seconds (1 year)."
                        )
                        f.seal_evidence()
                        findings.append(f)

                if "includesubdomains" not in hsts_lower:
                    f = PassiveFinding(
                        rule_id="PASSIVE-HDR-HSTS-NO-SUBDOMAINS",
                        title="HSTS Missing includeSubDomains Directive",
                        description="The HSTS header does not include the includeSubDomains directive, leaving subdomains vulnerable to downgrade attacks.",
                        cwe_id="CWE-319",
                        owasp_category="A02:2021 - Cryptographic Failures",
                        severity=Severity.LOW,
                        cvss_score=3.1,
                        status=FindingStatus.DETECTED,
                        confidence=0.9,
                        url=context.url,
                        evidence_response=f"Strict-Transport-Security: {hsts}",
                        remediation="Append 'includeSubDomains' to the Strict-Transport-Security header."
                    )
                    f.seal_evidence()
                    findings.append(f)

        # 3. X-Content-Type-Options
        xcto = context.get_header("x-content-type-options")
        if not xcto or xcto.strip().lower() != "nosniff":
            f = PassiveFinding(
                rule_id="PASSIVE-HDR-XCTO-MISSING",
                title="Missing or Invalid X-Content-Type-Options Header",
                description="The X-Content-Type-Options header is missing or not set to 'nosniff', allowing browsers to MIME-sniff response content.",
                cwe_id="CWE-693",
                owasp_category="A05:2021 - Security Misconfiguration",
                severity=Severity.LOW,
                cvss_score=3.7,
                status=FindingStatus.DETECTED,
                confidence=0.95,
                url=context.url,
                evidence_response=f"X-Content-Type-Options: {xcto or '[MISSING]'}",
                remediation="Configure the server to return 'X-Content-Type-Options: nosniff'."
            )
            f.seal_evidence()
            findings.append(f)

        # 4. X-Frame-Options (Clickjacking)
        xfo = context.get_header("x-frame-options")
        has_frame_ancestors = bool(csp and "frame-ancestors" in csp.lower())
        if is_html and not xfo and not has_frame_ancestors:
            f = PassiveFinding(
                rule_id="PASSIVE-HDR-XFO-MISSING",
                title="Missing Anti-Clickjacking Header (X-Frame-Options / frame-ancestors)",
                description="The HTML page does not set X-Frame-Options or CSP frame-ancestors, enabling the page to be rendered within an attacker-controlled iframe.",
                cwe_id="CWE-1021",
                owasp_category="A05:2021 - Security Misconfiguration",
                severity=Severity.MEDIUM,
                cvss_score=4.8,
                status=FindingStatus.DETECTED,
                confidence=0.9,
                url=context.url,
                evidence_response="Neither X-Frame-Options nor CSP frame-ancestors directive was detected.",
                remediation="Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN', or use CSP 'frame-ancestors 'self''."
            )
            f.seal_evidence()
            findings.append(f)
        elif xfo and "allow-from" in xfo.lower():
            f = PassiveFinding(
                rule_id="PASSIVE-HDR-XFO-DEPRECATED",
                title="Deprecated X-Frame-Options ALLOW-FROM Directive In Use",
                description="The X-Frame-Options header uses the obsolete ALLOW-FROM directive, which is ignored by modern browsers.",
                cwe_id="CWE-1021",
                owasp_category="A05:2021 - Security Misconfiguration",
                severity=Severity.LOW,
                cvss_score=2.8,
                status=FindingStatus.DETECTED,
                confidence=0.9,
                url=context.url,
                evidence_response=f"X-Frame-Options: {xfo}",
                remediation="Use CSP frame-ancestors instead of the deprecated X-Frame-Options ALLOW-FROM directive."
            )
            f.seal_evidence()
            findings.append(f)

        # 5. Referrer-Policy
        ref_pol = context.get_header("referrer-policy")
        if not ref_pol:
            f = PassiveFinding(
                rule_id="PASSIVE-HDR-REFERRER-MISSING",
                title="Missing Referrer-Policy Header",
                description="The Referrer-Policy header is missing, which may leak sensitive query parameters or internal paths in outbound Referer headers.",
                cwe_id="CWE-200",
                owasp_category="A05:2021 - Security Misconfiguration",
                severity=Severity.LOW,
                cvss_score=3.1,
                status=FindingStatus.DETECTED,
                confidence=0.9,
                url=context.url,
                evidence_response="Referrer-Policy header not set.",
                remediation="Set 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'."
            )
            f.seal_evidence()
            findings.append(f)
        elif ref_pol.strip().lower() in ("unsafe-url", "no-referrer-when-downgrade"):
            f = PassiveFinding(
                rule_id="PASSIVE-HDR-REFERRER-UNSAFE",
                title="Weak or Unsafe Referrer-Policy Configured",
                description=f"The Referrer-Policy is set to '{ref_pol}', leaking full request URLs across origin boundaries.",
                cwe_id="CWE-200",
                owasp_category="A05:2021 - Security Misconfiguration",
                severity=Severity.LOW,
                cvss_score=3.5,
                status=FindingStatus.DETECTED,
                confidence=0.9,
                url=context.url,
                evidence_response=f"Referrer-Policy: {ref_pol}",
                remediation="Change Referrer-Policy to 'strict-origin-when-cross-origin' or 'same-origin'."
            )
            f.seal_evidence()
            findings.append(f)

        # 6. Permissions-Policy / Feature-Policy
        perm_pol = context.get_header("permissions-policy") or context.get_header("feature-policy")
        if is_html and not perm_pol:
            f = PassiveFinding(
                rule_id="PASSIVE-HDR-PERMISSIONS-MISSING",
                title="Missing Permissions-Policy Header",
                description="The web application does not define a Permissions-Policy header to restrict powerful browser features like camera, microphone, and geolocation.",
                cwe_id="CWE-693",
                owasp_category="A05:2021 - Security Misconfiguration",
                severity=Severity.LOW,
                cvss_score=2.6,
                status=FindingStatus.DETECTED,
                confidence=0.85,
                url=context.url,
                evidence_response="Neither Permissions-Policy nor Feature-Policy header was found.",
                remediation="Implement a Permissions-Policy header restricting sensitive hardware APIs (e.g. camera=(), microphone=(), geolocation=())."
            )
            f.seal_evidence()
            findings.append(f)
        elif perm_pol:
            perm_lower = perm_pol.lower()
            if re.search(r'(?:camera|microphone|geolocation)=\*', perm_lower):
                f = PassiveFinding(
                    rule_id="PASSIVE-HDR-PERMISSIONS-PERMISSIVE",
                    title="Overly Permissive Permissions-Policy (Wildcard * Feature Access)",
                    description="The Permissions-Policy allows wildcard '*' access to sensitive device sensors like camera, microphone, or geolocation.",
                    cwe_id="CWE-693",
                    owasp_category="A05:2021 - Security Misconfiguration",
                    severity=Severity.LOW,
                    cvss_score=3.2,
                    status=FindingStatus.DETECTED,
                    confidence=0.9,
                    url=context.url,
                    evidence_response=f"Permissions-Policy: {perm_pol}",
                    remediation="Restrict feature permissions to 'self' or explicit trusted domains instead of wildcard '*'."
                )
                f.seal_evidence()
                findings.append(f)

        return findings
