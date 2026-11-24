import re
from typing import List, Set
from urllib.parse import urlparse
from bs4 import BeautifulSoup, Comment

from backend.app.scanner.passive.base import BasePassiveAnalyzer
from backend.app.scanner.passive.models import HTTPResponseContext, PassiveFinding
from shared.schemas.common import Severity, FindingStatus


class HTMLSecurityAnalyzer(BasePassiveAnalyzer):
    """Passive analyzer for HTML DOM structures: missing SRI, sensitive comments, form security, and meta tags."""

    analyzer_id = "HTML-SEC-ANALYZER"
    analyzer_name = "HTML DOM & Document Security Analyzer"
    category = "HTML Security"
    supported_rules = [
        "PASSIVE-HTML-SRI-MISSING",
        "PASSIVE-HTML-MISSING-CHARSET",
        "PASSIVE-HTML-MISSING-VIEWPORT",
        "PASSIVE-HTML-FORM-CLEAR-ACTION",
        "PASSIVE-HTML-FORM-PASSWORD-CLEAR",
        "PASSIVE-HTML-FORM-NO-CSRF-TOKEN",
        "PASSIVE-HTML-SENSITIVE-COMMENT"
    ]

    # Sensitive keywords inside HTML comments
    SENSITIVE_COMMENT_PATTERN = re.compile(
        r'(?i)\b(password|passwd|secret|api[_-]?key|admin|credentials|token|auth_token|todo:?\s*fix|fixme:?\s*sec)\b'
    )

    # Common CDN domains for script inclusion
    CDN_HOST_PATTERNS = [
        "cdn.jsdelivr.net",
        "cdnjs.cloudflare.com",
        "code.jquery.com",
        "unpkg.com",
        "stackpath.bootstrapcdn.com",
        "ajax.googleapis.com"
    ]

    THIRD_PARTY_EXTERNAL_DOMAINS = {
        "google.com", "bing.com", "duckduckgo.com", "yahoo.com", "paypal.com",
        "facebook.com", "twitter.com", "linkedin.com", "accounts.google.com"
    }

    CSRF_TOKEN_FIELD_NAMES = {
        "csrf", "csrftoken", "_csrf", "csrf_token", "_token", "authenticity_token",
        "xsrf", "xsrf_token", "_xsrf", "antiforgery", "__requestverificationtoken"
    }

    def analyze(self, context: HTTPResponseContext) -> List[PassiveFinding]:
        findings: List[PassiveFinding] = []
        is_html = "text/html" in (context.get_header("content-type") or "").lower()
        if not is_html or not context.body:
            return findings

        parsed_base_url = urlparse(context.url)
        is_https = parsed_base_url.scheme.lower() == "https"

        try:
            soup = BeautifulSoup(context.body, "html.parser")
        except Exception:
            return findings

        # 1. Missing Security-Related Metadata (Charset & Viewport)
        # Check if charset is already declared in HTTP Content-Type header (e.g. text/html; charset=utf-8)
        content_type_hdr = (context.get_header("content-type") or "").lower()
        has_http_header_charset = "charset=" in content_type_hdr

        if not has_http_header_charset:
            charset_tag = soup.find("meta", charset=True) or soup.find("meta", attrs={"http-equiv": lambda v: v and "content-type" in v.lower()})
            if not charset_tag:
                f = PassiveFinding(
                    rule_id="PASSIVE-HTML-MISSING-CHARSET",
                    title="Missing Character Encoding (<meta charset>) Declaration in HTML Document",
                    description="The HTML document does not explicitly specify a character encoding (such as UTF-8) and the HTTP response header lacks a charset parameter, exposing the document to character-set confusion.",
                    cwe_id="CWE-436",
                    owasp_category="A05:2021 - Security Misconfiguration",
                    severity=Severity.INFORMATIONAL,
                    cvss_score=2.0,
                    status=FindingStatus.DETECTED,
                    confidence=0.9,
                    url=context.url,
                    evidence_response="No <meta charset='utf-8'> tag found in document <head> and Content-Type header lacks charset.",
                    remediation="Add '<meta charset=\"utf-8\">' as the first element inside the document's <head> section or configure the web server to declare charset in Content-Type."
                )
                f.seal_evidence()
                findings.append(f)

        viewport_tag = soup.find("meta", attrs={"name": lambda v: v and v.lower() == "viewport"})
        if not viewport_tag:
            f = PassiveFinding(
                rule_id="PASSIVE-HTML-MISSING-VIEWPORT",
                title="Missing Responsive Viewport Meta Tag (<meta name='viewport'>)",
                description="The document lacks a viewport definition, which can compromise security usability and mobile UI framing.",
                cwe_id="CWE-1021",
                owasp_category="A05:2021 - Security Misconfiguration",
                severity=Severity.INFORMATIONAL,
                cvss_score=1.5,
                status=FindingStatus.DETECTED,
                confidence=0.85,
                url=context.url,
                evidence_response="No <meta name='viewport'> tag detected.",
                remediation="Add '<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">'."
            )
            f.seal_evidence()
            findings.append(f)

        # 2. Subresource Integrity (SRI) for External Scripts
        external_scripts_without_sri = []
        for script in soup.find_all("script", src=True):
            src = script["src"].strip()
            src_parsed = urlparse(src)
            is_external_cdn = any(cdn in src_parsed.netloc.lower() for cdn in self.CDN_HOST_PATTERNS)
            if is_external_cdn and not script.get("integrity"):
                external_scripts_without_sri.append(src)

        if external_scripts_without_sri:
            sample_scripts = "\n".join(external_scripts_without_sri[:5])
            f = PassiveFinding(
                rule_id="PASSIVE-HTML-SRI-MISSING",
                title="External Third-Party Scripts Loaded Without Subresource Integrity (SRI)",
                description="The application loads JavaScript files from third-party CDNs without cryptographic SRI hashes. If the CDN is compromised, attackers can execute arbitrary code in users' browsers.",
                cwe_id="CWE-353",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                severity=Severity.LOW,
                cvss_score=3.7,
                status=FindingStatus.DETECTED,
                confidence=0.9,
                url=context.url,
                evidence_response=f"[Scripts Missing integrity Attribute]\n{sample_scripts}",
                remediation="Include 'integrity=\"sha384-...\"' and 'crossorigin=\"anonymous\"' attributes on all external CDN script tags."
            )
            f.seal_evidence()
            findings.append(f)

        # 3. Form Security Configurations
        for form in soup.find_all("form"):
            action = form.get("action") or ""
            method = (form.get("method") or "GET").upper()
            action_parsed = urlparse(action)
            action_is_http = action_parsed.scheme.lower() == "http"

            # Form Action cleartext check
            if action_is_http:
                f = PassiveFinding(
                    rule_id="PASSIVE-HTML-FORM-CLEAR-ACTION",
                    title="HTML Form Submits Data Over Cleartext HTTP Action",
                    description=f"The form action URL ('{action}') uses unencrypted cleartext HTTP, transmitting submitted user form data in plain text.",
                    cwe_id="CWE-319",
                    owasp_category="A02:2021 - Cryptographic Failures",
                    severity=Severity.HIGH,
                    cvss_score=7.4,
                    status=FindingStatus.DETECTED,
                    confidence=0.95,
                    url=context.url,
                    evidence_response=f"<form action='{action}' method='{method}'>",
                    remediation="Change form action destinations to secure HTTPS endpoints."
                )
                f.seal_evidence()
                findings.append(f)

            # Password input checks
            password_inputs = form.find_all("input", attrs={"type": lambda t: t and t.lower() == "password"})
            if password_inputs:
                if not is_https or action_is_http:
                    f = PassiveFinding(
                        rule_id="PASSIVE-HTML-FORM-PASSWORD-CLEAR",
                        title="Password Form Field Present on Insecure / HTTP Page",
                        description="A password input field is rendered on an unencrypted page or submits to an unencrypted destination, allowing credentials to be captured in transit.",
                        cwe_id="CWE-319",
                        owasp_category="A02:2021 - Cryptographic Failures",
                        severity=Severity.HIGH,
                        cvss_score=8.1,
                        status=FindingStatus.DETECTED,
                        confidence=1.0,
                        url=context.url,
                        evidence_response=f"Password field inside <form action='{action}'>",
                        remediation="Host authentication and login forms exclusively on HTTPS with secure endpoints."
                    )
                    f.seal_evidence()
                    findings.append(f)

            # Missing Anti-CSRF token on POST forms (internal state-modifying actions)
            if method == "POST":
                # Check if form action targets an external third-party domain (e.g. search engine, external oauth)
                is_third_party = any(tpd in action_parsed.netloc.lower() for tpd in self.THIRD_PARTY_EXTERNAL_DOMAINS)
                if not is_third_party:
                    has_csrf = False
                    for inp in form.find_all(["input", "button"]):
                        field_name = (inp.get("name") or "").lower()
                        field_id = (inp.get("id") or "").lower()
                        if (
                            field_name in self.CSRF_TOKEN_FIELD_NAMES
                            or any(tok in field_name for tok in ("csrf", "xsrf", "antiforgery"))
                            or any(tok in field_id for tok in ("csrf", "xsrf"))
                        ):
                            has_csrf = True
                            break

                    if not has_csrf:
                        f = PassiveFinding(
                            rule_id="PASSIVE-HTML-FORM-NO-CSRF-TOKEN",
                            title="HTML POST Form Missing Explicit Anti-CSRF Token Field",
                            description="The HTML form uses HTTP POST but does not include a recognized anti-CSRF token hidden input field, potentially exposing the action to Cross-Site Request Forgery.",
                            cwe_id="CWE-352",
                            owasp_category="A01:2021 - Broken Access Control",
                            severity=Severity.MEDIUM,
                            cvss_score=5.4,
                            status=FindingStatus.DETECTED,
                            confidence=0.8,
                            url=context.url,
                            evidence_response=f"<form action='{action}' method='POST'> without CSRF token",
                            remediation="Embed a synchronized anti-CSRF token hidden field in every state-modifying POST form or validate SameSite cookie protections."
                        )
                        f.seal_evidence()
                        findings.append(f)

        # 4. Potentially Sensitive Information in HTML Comments
        comments = soup.find_all(string=lambda text: isinstance(text, Comment))
        sensitive_comments: List[str] = []
        for comment in comments:
            comment_text = str(comment).strip()
            if self.SENSITIVE_COMMENT_PATTERN.search(comment_text):
                sensitive_comments.append(comment_text)

        if sensitive_comments:
            sample_comment = sensitive_comments[0][:200]
            f = PassiveFinding(
                rule_id="PASSIVE-HTML-SENSITIVE-COMMENT",
                title="Potentially Sensitive Information or Developer Note in HTML Comment",
                description="HTML comments contain sensitive keywords (e.g. password, admin, secret, todo/fixme), disclosing internal architecture or pending security items to public viewers.",
                cwe_id="CWE-615",
                owasp_category="A05:2021 - Security Misconfiguration",
                severity=Severity.LOW,
                cvss_score=3.1,
                status=FindingStatus.DETECTED,
                confidence=0.85,
                url=context.url,
                evidence_response=f"<!-- {sample_comment} -->",
                remediation="Remove developer comments, credentials, and internal annotations before deploying to production."
            )
            f.seal_evidence()
            findings.append(f)

        return findings
