import re
import urllib.parse
from typing import List
from uuid import UUID

from shared.schemas.common import Severity, FindingStatus
from backend.app.scanner.active.base import BaseActiveAnalyzer
from backend.app.scanner.active.models import ActiveTarget, ActiveFinding, RequestBudgetTracker
from backend.app.scanner.crawler.client import AsyncHTTPClient


class SSRFAnalyzer(BaseActiveAnalyzer):
    """Safe Server-Side Request Forgery (SSRF) Candidate Identification Analyzer.
    
    Identifies URL parameters that appear to be used by server-side code to fetch remote resources.
    
    Safety Guarantee:
    - NEVER targets cloud metadata (169.254.169.254), localhost (127.0.0.1), private networks (RFC 1918),
      or link-local IPv6 addresses.
    - All scanner outbound requests pass strictly through ScopeGate.
    - Probes use a safe synthetic non-routable address (http://scan-probe.invalid/).
    - Classifies findings as SUSPECTED to avoid claiming unverified remote execution.
    """

    URL_PARAM_NAMES = {
        "url", "target", "dest", "destination", "redirect", "feed", "proxy", "endpoint",
        "uri", "path", "api_url", "fetch_url", "domain", "callback", "service_url", "webhook"
    }

    SSRF_ERROR_INDICATORS = [
        re.compile(r"could not resolve host|getaddrinfo failed|name or service not known", re.I),
        re.compile(r"connection refused|failed to connect to|network is unreachable", re.I),
        re.compile(r"curl error|urllib\.error|httpx\.connecterror|requests\.exceptions", re.I),
        re.compile(r"httpconnectionpool|max retries exceeded with url", re.I),
        re.compile(r"invalid host name|unknown host", re.I),
    ]

    @property
    def analyzer_id(self) -> str:
        return "ACT-SSRF-ANALYZER"

    @property
    def analyzer_name(self) -> str:
        return "Safe SSRF Candidate Identifier"

    @property
    def category(self) -> str:
        return "Server-Side Request Forgery"

    @property
    def supported_rules(self) -> List[str]:
        return ["ACT-SSRF-URL-PARAM"]

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

        for param_name, orig_val in orig_params:
            if not budget.can_request():
                break

            # Identify if parameter name matches typical SSRF targets
            is_url_candidate = param_name.lower() in self.URL_PARAM_NAMES or orig_val.startswith(("http://", "https://"))
            if not is_url_candidate:
                continue

            # Safe synthetic non-routable test address (RFC 2606 .invalid domain)
            safe_probe_target = "http://scan-probe.invalid/ashlynx_safe_ssrf_test"
            probe_query = [(k, safe_probe_target if k == param_name else v) for k, v in orig_params]
            probe_url = urllib.parse.urlunparse(
                (parsed.scheme, parsed.netloc, parsed.path, parsed.params, urllib.parse.urlencode(probe_query), parsed.fragment)
            )

            budget.consume(1)
            resp, _ = await client.get(probe_url)
            if not resp:
                continue

            resp_text = resp.text or ""
            # Check for outbound fetch failure or gateway error indicators
            indicator_matched = None
            for pat in self.SSRF_ERROR_INDICATORS:
                match = pat.search(resp_text)
                if match:
                    indicator_matched = match.group(0)
                    break

            is_gateway_anomaly = resp.status_code in (502, 504) and (target.baseline_status or 200) not in (502, 504)

            if indicator_matched or is_gateway_anomaly:
                evidence_desc = (
                    f"Matched network client error '{indicator_matched}'"
                    if indicator_matched
                    else f"Triggered HTTP {resp.status_code} Gateway error"
                )

                finding = ActiveFinding(
                    rule_id="ACT-SSRF-URL-PARAM",
                    title=f"Potential Server-Side Request Forgery Candidate in Parameter '{param_name}'",
                    description=(
                        f"Injecting a safe test URI into parameter '{param_name}' provoked backend connection behavior ({evidence_desc}). "
                        f"This suggests the server may fetch resources from user-supplied URLs."
                    ),
                    cwe_id="CWE-918",
                    owasp_category="A10:2021 - Server-Side Request Forgery (SSRF)",
                    severity=Severity.HIGH,
                    cvss_score=7.5,
                    status=FindingStatus.SUSPECTED,
                    confidence=0.75,
                    url=base_url,
                    parameter=param_name,
                    http_method=target.method,
                    evidence_request=f"GET {probe_url} HTTP/1.1",
                    evidence_response=f"HTTP {resp.status_code}\r\n\r\n{resp_text[:300]}",
                    remediation="Do not allow arbitrary remote URLs in server-side fetch requests. Enforce a strict domain whitelist and validate all resolved IPs against private/metadata CIDRs.",
                    detection_module=self.analyzer_id,
                    probe_count=1,
                )
                findings.append(finding)

        return findings
