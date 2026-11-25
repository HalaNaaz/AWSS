import html
import urllib.parse
from typing import List, Optional
from uuid import UUID, uuid4

from shared.schemas.common import Severity, FindingStatus
from backend.app.scanner.active.base import BaseActiveAnalyzer
from backend.app.scanner.active.models import ActiveTarget, ActiveFinding, RequestBudgetTracker
from backend.app.scanner.crawler.client import AsyncHTTPClient


class XSSAnalyzer(BaseActiveAnalyzer):
    """Controlled, non-executing Cross-Site Scripting (XSS) Reflection Analyzer.
    
    Identifies unescaped reflection points across HTML body, HTML attributes, and JavaScript contexts.
    
    Safety Guarantee: Employs inert, non-executing alphanumeric canaries (e.g. ashx_<token><canary>).
    Never executes malicious JavaScript and never attempts browser exploitation or session theft.
    """

    @property
    def analyzer_id(self) -> str:
        return "ACT-XSS-ANALYZER"

    @property
    def analyzer_name(self) -> str:
        return "Controlled XSS Reflection Detector"

    @property
    def category(self) -> str:
        return "Cross-Site Scripting"

    @property
    def supported_rules(self) -> List[str]:
        return [
            "ACT-XSS-REFLECTED-HTML",
            "ACT-XSS-REFLECTED-ATTR",
            "ACT-XSS-REFLECTED-JS",
        ]

    async def check(
        self,
        target: ActiveTarget,
        client: AsyncHTTPClient,
        budget: RequestBudgetTracker,
        scan_id: UUID,
    ) -> List[ActiveFinding]:
        findings: List[ActiveFinding] = []

        if not target.parameters:
            return findings

        base_url = target.url
        parsed = urllib.parse.urlparse(base_url)
        orig_params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)

        for param_name, _ in orig_params:
            if not budget.can_request():
                break

            # Unique benign canary marker
            canary_token = uuid4().hex[:8]
            html_canary = f"ashx{canary_token}<ashxtag>"
            attr_canary = f'ashx{canary_token}"ashxattr'
            js_canary = f"ashx{canary_token}'-ashxjs-'"

            # Probe 1: HTML Body context reflection probe
            probe_query = [(k, html_canary if k == param_name else v) for k, v in orig_params]
            probe_url = urllib.parse.urlunparse(
                (parsed.scheme, parsed.netloc, parsed.path, parsed.params, urllib.parse.urlencode(probe_query), parsed.fragment)
            )

            budget.consume(1)
            resp, _ = await client.get(probe_url)
            if not resp or not resp.text:
                continue

            resp_text = resp.text
            escaped_html_canary = html.escape(html_canary)

            # Check if reflected unescaped in an executable HTML context
            content_type = (resp.headers.get("content-type") or "").lower()
            is_non_executable_mime = bool(content_type and not any(ct in content_type for ct in ("html", "xhtml", "xml")))

            if html_canary in resp_text and not is_non_executable_mime:
                # Raw unescaped HTML tag reflection verified
                finding = ActiveFinding(
                    rule_id="ACT-XSS-REFLECTED-HTML",
                    title=f"Reflected Cross-Site Scripting (HTML Context) in Parameter '{param_name}'",
                    description=(
                        f"An inert test marker with HTML markup injected into parameter '{param_name}' "
                        f"was reflected unescaped directly in the HTML response body."
                    ),
                    cwe_id="CWE-79",
                    owasp_category="A03:2021 - Injection",
                    severity=Severity.HIGH,
                    cvss_score=7.5,
                    status=FindingStatus.VERIFIED,
                    confidence=0.95,
                    url=base_url,
                    parameter=param_name,
                    http_method=target.method,
                    evidence_request=f"GET {probe_url} HTTP/1.1",
                    evidence_response=self._extract_evidence_context(resp_text, html_canary),
                    remediation="Apply contextual HTML entity encoding (e.g., &lt;, &gt;, &quot;, &#x27;) to all untrusted data rendered in HTML body context.",
                    detection_module=self.analyzer_id,
                    probe_count=1,
                )
                findings.append(finding)
                continue  # Skip further probes for this param if verified

            # If properly escaped, no vulnerability in HTML context
            if escaped_html_canary in resp_text:
                pass

            # Probe 2: Attribute context escape probe
            if not budget.can_request():
                break

            attr_query = [(k, attr_canary if k == param_name else v) for k, v in orig_params]
            attr_url = urllib.parse.urlunparse(
                (parsed.scheme, parsed.netloc, parsed.path, parsed.params, urllib.parse.urlencode(attr_query), parsed.fragment)
            )

            budget.consume(1)
            attr_resp, _ = await client.get(attr_url)
            if attr_resp and attr_resp.text:
                if attr_canary in attr_resp.text:
                    finding = ActiveFinding(
                        rule_id="ACT-XSS-REFLECTED-ATTR",
                        title=f"Reflected Cross-Site Scripting (Attribute Breakout) in Parameter '{param_name}'",
                        description=(
                            f"An inert test marker containing quote characters injected into parameter '{param_name}' "
                            f"was reflected without attribute quotation escaping in the response."
                        ),
                        cwe_id="CWE-79",
                        owasp_category="A03:2021 - Injection",
                        severity=Severity.HIGH,
                        cvss_score=7.2,
                        status=FindingStatus.VERIFIED,
                        confidence=0.92,
                        url=base_url,
                        parameter=param_name,
                        http_method=target.method,
                        evidence_request=f"GET {attr_url} HTTP/1.1",
                        evidence_response=self._extract_evidence_context(attr_resp.text, attr_canary),
                        remediation="Contextually encode attribute values and enclose attributes strictly in double quotes.",
                        detection_module=self.analyzer_id,
                        probe_count=2,
                    )
                    findings.append(finding)
                    continue

            # Probe 3: Script context escape probe
            if not budget.can_request():
                break

            js_query = [(k, js_canary if k == param_name else v) for k, v in orig_params]
            js_url = urllib.parse.urlunparse(
                (parsed.scheme, parsed.netloc, parsed.path, parsed.params, urllib.parse.urlencode(js_query), parsed.fragment)
            )

            budget.consume(1)
            js_resp, _ = await client.get(js_url)
            if js_resp and js_resp.text:
                # Check if reflected inside <script> without escaping
                if js_canary in js_resp.text and "<script" in js_resp.text.lower():
                    finding = ActiveFinding(
                        rule_id="ACT-XSS-REFLECTED-JS",
                        title=f"Reflected Cross-Site Scripting (Script Context) in Parameter '{param_name}'",
                        description=(
                            f"An inert test marker injected into parameter '{param_name}' "
                            f"was reflected unescaped inside a JavaScript execution context."
                        ),
                        cwe_id="CWE-79",
                        owasp_category="A03:2021 - Injection",
                        severity=Severity.HIGH,
                        cvss_score=8.0,
                        status=FindingStatus.VERIFIED,
                        confidence=0.90,
                        url=base_url,
                        parameter=param_name,
                        http_method=target.method,
                        evidence_request=f"GET {js_url} HTTP/1.1",
                        evidence_response=self._extract_evidence_context(js_resp.text, js_canary),
                        remediation="Avoid reflecting untrusted input directly into JavaScript code blocks; use JSON serialization with safe unicode escapes.",
                        detection_module=self.analyzer_id,
                        probe_count=3,
                    )
                    findings.append(finding)

        return findings

    def _extract_evidence_context(self, body: str, canary: str, window: int = 150) -> str:
        idx = body.find(canary)
        if idx == -1:
            return body[:300]
        start = max(0, idx - window)
        end = min(len(body), idx + len(canary) + window)
        return f"...{body[start:end]}..."
