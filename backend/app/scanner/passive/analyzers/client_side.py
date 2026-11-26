import re
from typing import List
from urllib.parse import urlparse
from bs4 import BeautifulSoup

from backend.app.scanner.passive.base import BasePassiveAnalyzer
from backend.app.scanner.passive.models import HTTPResponseContext, PassiveFinding
from shared.schemas.common import Severity, FindingStatus


class ClientSideSecurityAnalyzer(BasePassiveAnalyzer):
    """Passive analyzer for client-side DOM sinks, tabnabbing, postMessage, and mixed content."""

    analyzer_id = "CLIENT-SEC-ANALYZER"
    analyzer_name = "Client-Side & DOM Security Analyzer"
    category = "Client-Side Security"
    supported_rules = [
        "PASSIVE-CLIENT-TABNABBING",
        "PASSIVE-CLIENT-DOM-SINK",
        "PASSIVE-CLIENT-POSTMESSAGE-WILDCARD",
        "PASSIVE-CLIENT-MIXED-CONTENT",
    ]

    DOM_SOURCE_PATTERN = re.compile(
        r"\b(?:location\.search|location\.hash|location\.href|document\.URL|document\.referrer|window\.name)\b"
    )
    DOM_SINK_PATTERN = re.compile(
        r"(?:\.innerHTML\s*=|\.outerHTML\s*=|document\.write\s*\(|eval\s*\(|new\s+Function\s*\()"
    )
    POSTMESSAGE_WILDCARD_PATTERN = re.compile(r"\.postMessage\s*\([^)]*,\s*['\"]\*['\"]\s*\)")

    def analyze(self, context: HTTPResponseContext) -> List[PassiveFinding]:
        findings: List[PassiveFinding] = []
        content_type = (context.get_header("content-type") or "").lower()
        is_html = "text/html" in content_type
        if not is_html or not context.body:
            return findings

        parsed_base = urlparse(context.url)
        is_https = parsed_base.scheme.lower() == "https"

        try:
            soup = BeautifulSoup(context.body, "html.parser")
        except Exception:
            return findings

        # 1. Reverse Tabnabbing (<a target="_blank"> external links without noopener/noreferrer)
        for anchor in soup.find_all("a", target=True):
            if str(anchor.get("target", "")).lower() != "_blank":
                continue
            href = str(anchor.get("href", "")).strip()
            if not href.startswith(("http://", "https://", "//")):
                continue
            href_host = urlparse(href if not href.startswith("//") else f"https:{href}").netloc.lower()
            if href_host and href_host != parsed_base.netloc.lower():
                rel_vals = {r.lower() for r in (anchor.get("rel") or [])}
                if "noopener" not in rel_vals and "noreferrer" not in rel_vals:
                    f = PassiveFinding(
                        rule_id="PASSIVE-CLIENT-TABNABBING",
                        title="External target='_blank' Link Missing rel='noopener noreferrer'",
                        description=(
                            f"External link '{href}' opens in a new tab with target='_blank' without 'noopener' or 'noreferrer', "
                            f"exposing legacy browsers to window.opener reverse tabnabbing."
                        ),
                        cwe_id="CWE-1022",
                        owasp_category="A05:2021 - Security Misconfiguration",
                        severity=Severity.LOW,
                        cvss_score=3.1,
                        status=FindingStatus.DETECTED,
                        confidence=0.90,
                        url=context.url,
                        evidence_response=str(anchor)[:200],
                        remediation="Add rel='noopener noreferrer' to all external links using target='_blank'.",
                    )
                    f.seal_evidence()
                    findings.append(f)
                    break

        # 2. Inline Script DOM Sinks & postMessage Wildcard
        for script in soup.find_all("script"):
            script_text = script.string or script.get_text() or ""
            if not script_text.strip():
                continue

            if self.DOM_SOURCE_PATTERN.search(script_text) and self.DOM_SINK_PATTERN.search(script_text):
                f = PassiveFinding(
                    rule_id="PASSIVE-CLIENT-DOM-SINK",
                    title="Potential Client-Side DOM XSS Source-to-Sink Pattern",
                    description=(
                        f"An inline script on '{context.url}' references both a user-controllable DOM source "
                        f"(e.g., location.search/hash) and a dangerous execution/HTML sink (e.g., innerHTML, eval, document.write)."
                    ),
                    cwe_id="CWE-79",
                    owasp_category="A03:2021 - Injection",
                    severity=Severity.MEDIUM,
                    cvss_score=5.4,
                    status=FindingStatus.DETECTED,
                    confidence=0.80,
                    url=context.url,
                    evidence_response=script_text.strip()[:250],
                    remediation="Replace innerHTML/document.write/eval with safe DOM APIs such as textContent and strict sanitization.",
                )
                f.seal_evidence()
                findings.append(f)
                break

        for script in soup.find_all("script"):
            script_text = script.string or script.get_text() or ""
            pm_match = self.POSTMESSAGE_WILDCARD_PATTERN.search(script_text)
            if pm_match:
                f = PassiveFinding(
                    rule_id="PASSIVE-CLIENT-POSTMESSAGE-WILDCARD",
                    title="Wildcard Origin ('*') Used in window.postMessage()",
                    description=(
                        f"An inline script on '{context.url}' calls postMessage with wildcard targetOrigin '*', "
                        f"potentially leaking cross-window messages to untrusted origins."
                    ),
                    cwe_id="CWE-346",
                    owasp_category="A01:2021 - Broken Access Control",
                    severity=Severity.LOW,
                    cvss_score=4.3,
                    status=FindingStatus.DETECTED,
                    confidence=0.88,
                    url=context.url,
                    evidence_response=pm_match.group(0)[:200],
                    remediation="Specify the exact expected targetOrigin instead of '*' when calling postMessage().",
                )
                f.seal_evidence()
                findings.append(f)
                break

        # 3. HTTPS Mixed Content Active References
        if is_https:
            for tag_name, attr in [("script", "src"), ("iframe", "src"), ("link", "href"), ("form", "action")]:
                for el in soup.find_all(tag_name):
                    ref = str(el.get(attr, "")).strip()
                    if ref.lower().startswith("http://"):
                        f = PassiveFinding(
                            rule_id="PASSIVE-CLIENT-MIXED-CONTENT",
                            title="HTTPS Page References Cleartext HTTP Resource (Mixed Content)",
                            description=(
                                f"HTTPS page '{context.url}' loads or submits to cleartext resource '{ref}' via <{tag_name} {attr}>, "
                                f"undermining transport integrity."
                            ),
                            cwe_id="CWE-319",
                            owasp_category="A02:2021 - Cryptographic Failures",
                            severity=Severity.MEDIUM,
                            cvss_score=5.3,
                            status=FindingStatus.DETECTED,
                            confidence=0.95,
                            url=context.url,
                            evidence_response=str(el)[:200],
                            remediation="Serve all scripts, stylesheets, iframes, and form targets exclusively over HTTPS.",
                        )
                        f.seal_evidence()
                        findings.append(f)
                        return findings

        return findings
