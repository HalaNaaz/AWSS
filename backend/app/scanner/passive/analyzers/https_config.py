import re
from typing import List
from urllib.parse import urlparse
from bs4 import BeautifulSoup

from backend.app.scanner.passive.base import BasePassiveAnalyzer
from backend.app.scanner.passive.models import HTTPResponseContext, PassiveFinding
from shared.schemas.common import Severity, FindingStatus


class HTTPSConfigAnalyzer(BasePassiveAnalyzer):
    """Passive analyzer assessing transport security, unencrypted HTTP usage, mixed-content, and insecure redirects."""

    analyzer_id = "HTTPS-CONFIG-ANALYZER"
    analyzer_name = "HTTPS Transport Security & Mixed-Content Analyzer"
    category = "HTTPS Configuration"
    supported_rules = [
        "PASSIVE-HTTPS-INSECURE-SCHEME",
        "PASSIVE-HTTPS-ACTIVE-MIXED-CONTENT",
        "PASSIVE-HTTPS-PASSIVE-MIXED-CONTENT",
        "PASSIVE-HTTPS-INSECURE-REDIRECT"
    ]

    def analyze(self, context: HTTPResponseContext) -> List[PassiveFinding]:
        findings: List[PassiveFinding] = []
        parsed_url = urlparse(context.url)
        is_https = parsed_url.scheme.lower() == "https"

        # 1. Endpoint served over plain unencrypted HTTP
        if not is_https:
            f = PassiveFinding(
                rule_id="PASSIVE-HTTPS-INSECURE-SCHEME",
                title="Web Endpoint Served Over Cleartext HTTP Protocol",
                description="The web resource is transmitted over cleartext HTTP without transport-layer encryption (TLS), leaving communication susceptible to interception and tampering.",
                cwe_id="CWE-319",
                owasp_category="A02:2021 - Cryptographic Failures",
                severity=Severity.MEDIUM,
                cvss_score=5.9,
                status=FindingStatus.DETECTED,
                confidence=1.0,
                url=context.url,
                evidence_response=f"Cleartext URL visited: {context.url}",
                remediation="Enforce HTTPS across all application endpoints and configure HTTP to redirect to HTTPS automatically."
            )
            f.seal_evidence()
            findings.append(f)

        # 2. Insecure Redirect from HTTPS to HTTP (Downgrade)
        if context.status_code in (301, 302, 303, 307, 308) and is_https:
            location = context.get_header("location")
            if location and location.strip().lower().startswith("http://"):
                f = PassiveFinding(
                    rule_id="PASSIVE-HTTPS-INSECURE-REDIRECT",
                    title="Insecure Transport Downgrade: HTTPS Endpoint Redirects to Cleartext HTTP",
                    description=f"The secure HTTPS endpoint redirects visitors to an unencrypted HTTP destination ('{location}'), defeating TLS protection.",
                    cwe_id="CWE-319",
                    owasp_category="A02:2021 - Cryptographic Failures",
                    severity=Severity.HIGH,
                    cvss_score=7.4,
                    status=FindingStatus.DETECTED,
                    confidence=1.0,
                    url=context.url,
                    evidence_response=f"Status: {context.status_code}\nLocation: {location}",
                    remediation="Ensure all redirect targets retain the HTTPS scheme and never downgrade visitors to cleartext HTTP."
                )
                f.seal_evidence()
                findings.append(f)

        # 3. Mixed Content Analysis (only relevant on HTTPS HTML pages)
        if is_https and context.body and "text/html" in (context.get_header("content-type") or "").lower():
            try:
                soup = BeautifulSoup(context.body, "html.parser")

                # Active mixed content: <script src="http://">, <link rel="stylesheet" href="http://">, <iframe src="http://">
                active_mixed: List[str] = []
                for s in soup.find_all("script", src=True):
                    if s["src"].strip().lower().startswith("http://"):
                        active_mixed.append(f"<script src='{s['src']}'>")

                for l in soup.find_all("link", rel=lambda r: r and "stylesheet" in r.lower(), href=True):
                    if l["href"].strip().lower().startswith("http://"):
                        active_mixed.append(f"<link rel='stylesheet' href='{l['href']}'>")

                for f_tag in soup.find_all("iframe", src=True):
                    if f_tag["src"].strip().lower().startswith("http://"):
                        active_mixed.append(f"<iframe src='{f_tag['src']}'>")

                if active_mixed:
                    sample = "\n".join(active_mixed[:5])
                    f = PassiveFinding(
                        rule_id="PASSIVE-HTTPS-ACTIVE-MIXED-CONTENT",
                        title="Active Mixed Content Detected in HTTPS Document (Scripts / CSS / Iframes)",
                        description="The HTTPS document loads active executable resources (scripts, stylesheets, or iframes) over unencrypted HTTP, allowing man-in-the-middle attackers to inject malicious script into the secure page.",
                        cwe_id="CWE-311",
                        owasp_category="A02:2021 - Cryptographic Failures",
                        severity=Severity.HIGH,
                        cvss_score=7.5,
                        status=FindingStatus.DETECTED,
                        confidence=0.95,
                        url=context.url,
                        evidence_response=f"[Active Mixed Content Elements Discovered]\n{sample}",
                        remediation="Update all resource URLs to use HTTPS schemes or protocol-relative references."
                    )
                    f.seal_evidence()
                    findings.append(f)

                # Passive mixed content: <img src="http://">, <audio src="http://">, <video src="http://">
                passive_mixed: List[str] = []
                for img in soup.find_all("img", src=True):
                    if img["src"].strip().lower().startswith("http://"):
                        passive_mixed.append(f"<img src='{img['src']}'>")

                for media in soup.find_all(["audio", "video"]):
                    src = media.get("src")
                    if src and src.strip().lower().startswith("http://"):
                        passive_mixed.append(f"<{media.name} src='{src}'>")

                if passive_mixed:
                    sample = "\n".join(passive_mixed[:5])
                    f = PassiveFinding(
                        rule_id="PASSIVE-HTTPS-PASSIVE-MIXED-CONTENT",
                        title="Passive Mixed Content Detected in HTTPS Document (Images / Media)",
                        description="The HTTPS page loads passive display resources (images or media) over cleartext HTTP, which attackers can modify or monitor.",
                        cwe_id="CWE-311",
                        owasp_category="A02:2021 - Cryptographic Failures",
                        severity=Severity.LOW,
                        cvss_score=3.7,
                        status=FindingStatus.DETECTED,
                        confidence=0.9,
                        url=context.url,
                        evidence_response=f"[Passive Mixed Content Elements Discovered]\n{sample}",
                        remediation="Serve all images and media assets over encrypted HTTPS connections."
                    )
                    f.seal_evidence()
                    findings.append(f)

            except Exception:
                pass

        return findings
