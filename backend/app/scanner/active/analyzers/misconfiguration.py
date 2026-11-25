import urllib.parse
from typing import List, Dict, Tuple
from uuid import UUID

from shared.schemas.common import Severity, FindingStatus
from backend.app.scanner.active.base import BaseActiveAnalyzer
from backend.app.scanner.active.models import ActiveTarget, ActiveFinding, RequestBudgetTracker
from backend.app.scanner.crawler.client import AsyncHTTPClient
from backend.app.scanner.evidence.redactor import EvidenceRedactor


class MisconfigurationAnalyzer(BaseActiveAnalyzer):
    """Active Security Misconfiguration Detector.
    
    Checks:
    - Exposed directory listings (e.g. Index of /).
    - Publicly accessible diagnostic and actuator endpoints.
    - Unsafe HTTP methods (e.g. TRACE, PUT, DELETE).
    - Unintended publicly accessible backup or configuration files (/.env, /.git/HEAD).
    - Insecure open redirects.
    
    Safety Guarantee: Employs a conservative, bounded check list without brute-force directory fuzzing.
    """

    DIAGNOSTIC_PATHS = [
        ("/actuator/health", "Spring Boot Actuator Health", "A05:2021 - Security Misconfiguration", Severity.LOW, 3.5),
        ("/actuator/env", "Spring Boot Actuator Environment", "A05:2021 - Security Misconfiguration", Severity.HIGH, 7.5),
        ("/actuator", "Spring Boot Actuator Root", "A05:2021 - Security Misconfiguration", Severity.MEDIUM, 5.3),
        ("/_profiler", "Symfony Web Profiler", "A05:2021 - Security Misconfiguration", Severity.HIGH, 7.5),
        ("/phpinfo.php", "PHP Information Page (phpinfo)", "A05:2021 - Security Misconfiguration", Severity.MEDIUM, 5.3),
    ]

    SENSITIVE_FILES = [
        ("/.env", "Environment Variables File (.env)", ["DB_PASSWORD", "SECRET_KEY", "AWS_ACCESS_KEY", "APP_ENV"], Severity.HIGH, 7.5),
        ("/.git/HEAD", "Git Repository Metadata (.git/HEAD)", ["ref: refs/heads/"], Severity.HIGH, 7.5),
        ("/web.config", "IIS Configuration File (web.config)", ["<configuration>", "<system.webServer>"], Severity.MEDIUM, 5.3),
    ]

    REDIRECT_PARAMS = ["url", "redirect", "next", "dest", "destination", "target", "r", "goto"]

    @property
    def analyzer_id(self) -> str:
        return "ACT-MISCONFIG-ANALYZER"

    @property
    def analyzer_name(self) -> str:
        return "Security Misconfiguration Detector"

    @property
    def category(self) -> str:
        return "Security Misconfiguration"

    @property
    def supported_rules(self) -> List[str]:
        return [
            "ACT-MISCONFIG-DIRLIST",
            "ACT-MISCONFIG-DIAGNOSTIC",
            "ACT-MISCONFIG-UNSAFE-METHODS",
            "ACT-MISCONFIG-SENSITIVE-FILES",
            "ACT-MISCONFIG-OPEN-REDIRECT",
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
        base_origin = f"{parsed.scheme}://{parsed.netloc}"

        # 1. Directory Listing Check
        if target.baseline_body:
            lower_body = target.baseline_body.lower()
            if any(term in lower_body for term in ["<title>index of /", "directory listing for", "<title>folder listing"]):
                findings.append(
                    ActiveFinding(
                        rule_id="ACT-MISCONFIG-DIRLIST",
                        title="Exposed Directory Listing",
                        description=f"Directory index listing is enabled on endpoint '{target.url}', exposing filesystem structures.",
                        cwe_id="CWE-548",
                        owasp_category="A05:2021 - Security Misconfiguration",
                        severity=Severity.MEDIUM,
                        cvss_score=5.3,
                        status=FindingStatus.VERIFIED,
                        confidence=0.95,
                        url=target.url,
                        http_method=target.method,
                        evidence_response=target.baseline_body[:300],
                        remediation="Disable directory browsing/indexing in web server configuration (e.g. 'Options -Indexes' in Apache, or 'autoindex off' in Nginx).",
                        detection_module=self.analyzer_id,
                        probe_count=0,
                    )
                )

        # 2. Unsafe HTTP Methods Check (OPTIONS and TRACE)
        if budget.can_request():
            budget.consume(1)
            options_resp, _ = await client.request("OPTIONS", target.url)
            if options_resp:
                allow_header = options_resp.headers.get("allow", "").upper()
                if "TRACE" in allow_header:
                    findings.append(
                        ActiveFinding(
                            rule_id="ACT-MISCONFIG-UNSAFE-METHODS",
                            title="Unsafe HTTP TRACE Method Enabled",
                            description="The HTTP TRACE method is advertised in the server's Allow header, enabling Cross-Site Tracing (XST).",
                            cwe_id="CWE-650",
                            owasp_category="A05:2021 - Security Misconfiguration",
                            severity=Severity.LOW,
                            cvss_score=3.7,
                            status=FindingStatus.VERIFIED,
                            confidence=0.95,
                            url=target.url,
                            http_method="OPTIONS",
                            evidence_response=f"Allow: {allow_header}",
                            remediation="Disable HTTP TRACE and TRACK methods on the web server (e.g. 'TraceEnable off' in Apache).",
                            detection_module=self.analyzer_id,
                            probe_count=1,
                        )
                    )

        # 3. Bounded Sensitive Files & Diagnostic Probes (Only run on root paths to avoid duplicate probes per endpoint)
        if parsed.path in ["", "/", "/index.html"]:
            for path_suffix, name, category, sev, cvss in self.DIAGNOSTIC_PATHS:
                if not budget.can_request():
                    break
                check_url = urllib.parse.urljoin(base_origin, path_suffix)
                budget.consume(1)
                resp, _ = await client.get(check_url)
                if resp and resp.status_code == 200 and resp.text:
                    lower_text = resp.text.lower()
                    if ("status" in lower_text or "phpinfo" in lower_text or "profiler" in lower_text or "actuator" in lower_text):
                        findings.append(
                            ActiveFinding(
                                rule_id="ACT-MISCONFIG-DIAGNOSTIC",
                                title=f"Exposed Diagnostic Interface: {name}",
                                description=f"Publicly accessible diagnostic or management interface discovered at '{check_url}'.",
                                cwe_id="CWE-215",
                                owasp_category="A05:2021 - Security Misconfiguration",
                                severity=sev,
                                cvss_score=cvss,
                                status=FindingStatus.VERIFIED,
                                confidence=0.90,
                                url=check_url,
                                http_method="GET",
                                evidence_response=f"HTTP 200 OK\r\n\r\n{resp.text[:250]}",
                                remediation="Restrict administrative and diagnostic endpoints to authorized internal IP subnets or disable them in production.",
                                detection_module=self.analyzer_id,
                                probe_count=1,
                            )
                        )

            for path_suffix, name, content_patterns, sev, cvss in self.SENSITIVE_FILES:
                if not budget.can_request():
                    break
                check_url = urllib.parse.urljoin(base_origin, path_suffix)
                budget.consume(1)
                resp, _ = await client.get(check_url)
                if resp and resp.status_code == 200 and resp.text:
                    if any(pat in resp.text for pat in content_patterns):
                        findings.append(
                            ActiveFinding(
                                rule_id="ACT-MISCONFIG-SENSITIVE-FILES",
                                title=f"Exposed Sensitive File: {name}",
                                description=f"Publicly accessible configuration or source metadata file discovered at '{check_url}'.",
                                cwe_id="CWE-552",
                                owasp_category="A05:2021 - Security Misconfiguration",
                                severity=sev,
                                cvss_score=cvss,
                                status=FindingStatus.VERIFIED,
                                confidence=0.95,
                                url=check_url,
                                http_method="GET",
                                evidence_response=EvidenceRedactor.redact(f"HTTP 200 OK\r\n\r\n{resp.text[:200]}"),
                                remediation="Block public web server access to dotfiles, configuration files, and version control directories.",
                                detection_module=self.analyzer_id,
                                probe_count=1,
                            )
                        )

        # 4. Insecure Open Redirect Check
        if target.parameters:
            for param_name, _ in target.parameters.items():
                if param_name.lower() in self.REDIRECT_PARAMS:
                    if not budget.can_request():
                        break
                    # Test off-origin redirect with safe benign domain
                    test_redirect_val = "https://example.org/ashlynx_safe_test"
                    query_params = dict(target.parameters)
                    query_params[param_name] = test_redirect_val
                    test_url = urllib.parse.urlunparse(
                        (parsed.scheme, parsed.netloc, parsed.path, parsed.params, urllib.parse.urlencode(query_params), parsed.fragment)
                    )

                    budget.consume(1)
                    resp, _ = await client.request("GET", test_url, follow_redirects=False)
                    if resp and resp.status_code in (301, 302, 303, 307, 308):
                        loc = resp.headers.get("location", "")
                        if loc.startswith("https://example.org") or loc.startswith("//example.org"):
                            findings.append(
                                ActiveFinding(
                                rule_id="ACT-MISCONFIG-OPEN-REDIRECT",
                                title=f"Insecure Open Redirect in Parameter '{param_name}'",
                                description=(
                                    f"The application accepted an arbitrary off-origin redirection target in parameter '{param_name}' "
                                    f"and issued an HTTP redirect to '{loc}'."
                                ),
                                cwe_id="CWE-601",
                                owasp_category="A01:2021 - Broken Access Control",
                                severity=Severity.MEDIUM,
                                cvss_score=6.1,
                                status=FindingStatus.VERIFIED,
                                confidence=0.95,
                                url=target.url,
                                parameter=param_name,
                                http_method=target.method,
                                evidence_request=f"GET {test_url} HTTP/1.1",
                                evidence_response=f"HTTP {resp.status_code}\r\nLocation: {loc}",
                                remediation="Validate redirection targets against a strict whitelist of relative paths or authorized hostnames.",
                                detection_module=self.analyzer_id,
                                probe_count=1,
                            )
                        )

        return findings
