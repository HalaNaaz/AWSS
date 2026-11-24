import re
from typing import List, Pattern, Tuple
from backend.app.scanner.passive.base import BasePassiveAnalyzer
from backend.app.scanner.passive.models import HTTPResponseContext, PassiveFinding
from shared.schemas.common import Severity, FindingStatus


class InformationDisclosureAnalyzer(BasePassiveAnalyzer):
    """Passive analyzer detecting leaked technical metadata, server banners, debug headers, stack traces, and internal IPs."""

    analyzer_id = "INFO-DISC-ANALYZER"
    analyzer_name = "Information Disclosure & Diagnostic Leak Analyzer"
    category = "Information Disclosure"
    supported_rules = [
        "PASSIVE-INFO-SERVER-VERSION",
        "PASSIVE-INFO-FRAMEWORK-DISCLOSURE",
        "PASSIVE-INFO-DEBUG-HEADERS",
        "PASSIVE-INFO-STACKTRACE-BODY",
        "PASSIVE-INFO-INTERNAL-IP-LEAK",
        "PASSIVE-INFO-DATABASE-URI-LEAK"
    ]

    # Regex patterns for stack traces in HTML / text responses
    STACK_TRACE_PATTERNS: List[Tuple[str, Pattern, str]] = [
        (
            "Python / Django Stack Trace",
            re.compile(r'(?:Traceback \(most recent call last\):|File "[^"]+", line \d+, in |django\.core\.exceptions\.)', re.IGNORECASE),
            "Python exception traceback disclosed in response body."
        ),
        (
            "Java / Spring Stack Trace",
            re.compile(r'(?:org\.apache\.catalina\.|java\.lang\.[A-Za-z0-9]+Exception|at [a-zA-Z0-9_.]+\([a-zA-Z0-9_]+\.java:\d+\)|Whitelabel Error Page)', re.IGNORECASE),
            "Java exception stack trace or default framework error page disclosed."
        ),
        (
            "PHP Fatal Error / Stack Trace",
            re.compile(r'(?:Fatal error:\s*Uncaught|Warning:\s*(?:mysqli_|pg_|pdo_|include|require)|Stack trace:\s*#0\s*)', re.IGNORECASE),
            "PHP diagnostic error or execution stack trace disclosed."
        ),
        (
            ".NET / ASP.NET Stack Trace",
            re.compile(r'(?:System\.[A-Za-z0-9]+Exception:|Server Error in \'[^\']+\' Application\.|\[NullReferenceException:)', re.IGNORECASE),
            "Microsoft ASP.NET application error stack trace disclosed."
        ),
        (
            "Node.js / Express Stack Trace",
            re.compile(r'(?:Error:\s*connect ECONNREFUSED|at Layer\.handle \[as handle_request\]|at Function\.process_params)', re.IGNORECASE),
            "Node.js runtime error stack trace disclosed."
        )
    ]

    # Pattern for RFC 1918 Private IP leakage
    INTERNAL_IP_PATTERN = re.compile(
        r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b'
    )

    # Database connection string pattern
    DB_URI_PATTERN = re.compile(
        r'(?i)\b(?:postgres|postgresql|mysql|mongodb|redis|mssql|oracle):\/\/[^\s\'"<>\\]+'
    )

    def analyze(self, context: HTTPResponseContext) -> List[PassiveFinding]:
        findings: List[PassiveFinding] = []

        # 1. Server Header Version Disclosure
        server_hdr = context.get_header("server")
        if server_hdr:
            # Check if server contains version numbers (e.g., Apache/2.4.41, nginx/1.18.0)
            if re.search(r'[A-Za-z]+/\d+\.\d+', server_hdr):
                f = PassiveFinding(
                    rule_id="PASSIVE-INFO-SERVER-VERSION",
                    title="Web Server Software & Exact Version Disclosed in 'Server' Header",
                    description=f"The web server reveals its identity and exact version ('{server_hdr}'), assisting attackers in vulnerability targeting and exploit discovery.",
                    cwe_id="CWE-200",
                    owasp_category="A05:2021 - Security Misconfiguration",
                    severity=Severity.LOW,
                    cvss_score=3.1,
                    status=FindingStatus.DETECTED,
                    confidence=0.95,
                    url=context.url,
                    evidence_response=f"Server: {server_hdr}",
                    remediation="Configure web server to suppress granular version information (e.g., 'ServerTokens Prod' in Apache or 'server_tokens off;' in Nginx)."
                )
                f.seal_evidence()
                findings.append(f)

        # 2. Framework & Runtime Disclosure (X-Powered-By, X-AspNet-Version, etc.)
        powered_by = context.get_header("x-powered-by")
        aspnet_ver = context.get_header("x-aspnet-version")
        runtime_hdr = context.get_header("x-runtime")

        disclosed_frameworks = []
        if powered_by:
            disclosed_frameworks.append(f"X-Powered-By: {powered_by}")
        if aspnet_ver:
            disclosed_frameworks.append(f"X-AspNet-Version: {aspnet_ver}")
        if runtime_hdr:
            disclosed_frameworks.append(f"X-Runtime: {runtime_hdr}")

        if disclosed_frameworks:
            evidence_str = "\n".join(disclosed_frameworks)
            f = PassiveFinding(
                rule_id="PASSIVE-INFO-FRAMEWORK-DISCLOSURE",
                title="Application Framework & Runtime Architecture Disclosed in HTTP Headers",
                description="Response headers explicitly disclose backend technology stacks and runtimes, aiding reconnaissance and targeted attack vectors.",
                cwe_id="CWE-200",
                owasp_category="A05:2021 - Security Misconfiguration",
                severity=Severity.LOW,
                cvss_score=3.1,
                status=FindingStatus.DETECTED,
                confidence=0.95,
                url=context.url,
                evidence_response=evidence_str,
                remediation="Disable technology disclosure headers in backend frameworks (e.g. app.disable('x-powered-by') in Express, expose_php = Off in php.ini)."
            )
            f.seal_evidence()
            findings.append(f)

        # 3. Debug Diagnostic Headers
        debug_headers = [
            "x-debug-token",
            "x-debug-token-link",
            "x-werkzeug-pin",
            "x-clockwork-id",
            "x-debug",
            "x-profiler"
        ]
        active_debug_hdrs = []
        for dh in debug_headers:
            val = context.get_header(dh)
            if val:
                active_debug_hdrs.append(f"{dh}: {val}")

        if active_debug_hdrs:
            f = PassiveFinding(
                rule_id="PASSIVE-INFO-DEBUG-HEADERS",
                title="Active Debug / Profiler Headers Disclosed in Production Response",
                description="The application is returning diagnostic or profiling headers, indicating that development or debug mode may be active.",
                cwe_id="CWE-215",
                owasp_category="A05:2021 - Security Misconfiguration",
                severity=Severity.MEDIUM,
                cvss_score=5.3,
                status=FindingStatus.DETECTED,
                confidence=0.95,
                url=context.url,
                evidence_response="\n".join(active_debug_hdrs),
                remediation="Disable developer profiling, Symfony web profiler, or Werkzeug debuggers in production environments."
            )
            f.seal_evidence()
            findings.append(f)

        # Body checks (only if response body exists)
        if context.body:
            body_text = context.body

            # 4. Detailed Stack Trace & Diagnostic Dump
            for trace_name, pattern, explanation in self.STACK_TRACE_PATTERNS:
                match = pattern.search(body_text)
                if match:
                    # Extract surrounding snippet
                    start_idx = max(0, match.start() - 50)
                    end_idx = min(len(body_text), match.end() + 250)
                    snippet = body_text[start_idx:end_idx].strip()

                    f = PassiveFinding(
                        rule_id="PASSIVE-INFO-STACKTRACE-BODY",
                        title=f"Detailed Application Stack Trace Disclosed ({trace_name})",
                        description=f"{explanation} Detailed internal file paths, code snippets, and call stacks are exposed to clients.",
                        cwe_id="CWE-209",
                        owasp_category="A05:2021 - Security Misconfiguration",
                        severity=Severity.HIGH,
                        cvss_score=7.5,
                        status=FindingStatus.DETECTED,
                        confidence=0.95,
                        url=context.url,
                        evidence_response=f"[Disclosed Stack Trace Snippet]\n{snippet}",
                        remediation="Configure unified, generic custom error pages. Never expose unhandled runtime exceptions or stack traces to end users."
                    )
                    f.seal_evidence()
                    findings.append(f)
                    break  # Found primary stack trace

            # 5. Internal RFC 1918 Private IP Address Leak
            ip_matches = self.INTERNAL_IP_PATTERN.findall(body_text)
            # Filter out false-positive strings like subnet masks 255.255.255.0
            valid_internal_ips = set(
                ip for ip in ip_matches
                if not ip.endswith(".0") and not ip.endswith(".255") and ip != "127.0.0.1"
            )
            if valid_internal_ips:
                sample_ips = ", ".join(list(valid_internal_ips)[:5])
                f = PassiveFinding(
                    rule_id="PASSIVE-INFO-INTERNAL-IP-LEAK",
                    title="Internal RFC 1918 Private IP Address Disclosed in Response Body",
                    description=f"The application body leaks internal private IP addresses ({sample_ips}), revealing internal network topology.",
                    cwe_id="CWE-200",
                    owasp_category="A05:2021 - Security Misconfiguration",
                    severity=Severity.LOW,
                    cvss_score=3.7,
                    status=FindingStatus.DETECTED,
                    confidence=0.85,
                    url=context.url,
                    evidence_response=f"Internal IP addresses found: {sample_ips}",
                    remediation="Sanitize error messages, configuration pages, and internal network references before sending responses."
                )
                f.seal_evidence()
                findings.append(f)

            # 6. Database Connection String URI Leak
            db_match = self.DB_URI_PATTERN.search(body_text)
            if db_match:
                uri_str = db_match.group(0)
                f = PassiveFinding(
                    rule_id="PASSIVE-INFO-DATABASE-URI-LEAK",
                    title="Database Connection String or URI Leaked in Response Body",
                    description="The response body contains a database connection URI scheme, potentially leaking database credentials, hostnames, and ports.",
                    cwe_id="CWE-200",
                    owasp_category="A02:2021 - Cryptographic Failures",
                    severity=Severity.HIGH,
                    cvss_score=8.2,
                    status=FindingStatus.DETECTED,
                    confidence=0.95,
                    url=context.url,
                    evidence_response=f"Exposed Database URI pattern: {uri_str[:60]}...",
                    remediation="Ensure database connection strings are stored securely in environment variables and never printed to HTTP responses."
                )
                f.seal_evidence()
                findings.append(f)

        return findings
