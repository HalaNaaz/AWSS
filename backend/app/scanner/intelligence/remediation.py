from typing import Any, Dict, List, Optional

from backend.app.scanner.intelligence.normalizer import NormalizedFinding
from shared.schemas.intelligence import (
    ContextualPriority,
    ContextualRiskAssessmentSchema,
    RemediationIntelligenceSchema,
    RemediationPriority,
    RemediationStatus,
)


class RemediationIntelligenceEngine:
    """Phase 5G: Context-Aware, Evidence-Grounded Remediation Intelligence Engine.

    Generates structured, CWE-accurate, and technology-informed remediation
    guidance without fabricating CVE identifiers or external references.
    """

    KNOWLEDGE_BASE: Dict[str, Dict[str, Any]] = {
        "CWE-89": {
            "root_cause": "Untrusted input is concatenated or interpolated directly into dynamic SQL query statements without parameterization.",
            "why_it_matters": "Attackers can alter query syntax to read unauthorized database records, bypass authentication, or manipulate persisted data.",
            "recommended_remediation": "Replace dynamic SQL string construction with parameterized queries (prepared statements) or ORM bound parameters across all affected entry points.",
            "secure_guidance": "Use bound parameters (e.g., `cursor.execute('SELECT ... WHERE id = %s', (user_id,))` in Python DB-API / SQLAlchemy `text(...).bindparams(...)`, or parameterized queries in Express/Knex/Prisma). Enforce strict input type validation.",
            "verification": "Re-test the affected parameter with boolean differential probes (e.g., invariant true vs false conditions) and verify identical baseline responses with no SQL error strings.",
            "owasp": ["A03:2021 - Injection"],
            "prereqs": ["Database query audit of route handler and DAO/repository layer", "Automated integration tests for affected query path"],
        },
        "CWE-79": {
            "root_cause": "User-controlled input is reflected into the HTTP response DOM, HTML attribute, or script block without context-aware output encoding.",
            "why_it_matters": "Arbitrary JavaScript execution in the victim browser can hijack authenticated sessions, exfiltrate sensitive DOM data, or perform unauthorized actions.",
            "recommended_remediation": "Apply context-specific output encoding before rendering user input in HTML text nodes, attributes, or script blocks, and enforce a strict Content-Security-Policy (CSP).",
            "secure_guidance": "Use framework auto-escaping templates (React JSX `{val}`, Jinja2 autoescape=True), encode attribute values, avoid `dangerouslySetInnerHTML`/`innerHTML`, and deploy a nonce-based `Content-Security-Policy` blocking inline scripts.",
            "verification": "Submit an inert alphanumeric canary with HTML metacharacters (`<`, `>`, `\"`, `'`) to the parameter and confirm characters are HTML-entity encoded in the response.",
            "owasp": ["A03:2021 - Injection"],
            "prereqs": ["Identify rendering context (HTML body vs attribute vs JavaScript literal)", "Deploy non-breaking CSP in Report-Only before enforcement"],
        },
        "CWE-1336": {
            "root_cause": "Untrusted user input is passed directly into a server-side template compilation call rather than supplied as a template context variable.",
            "why_it_matters": "Template expression evaluation can expose internal server objects, configuration secrets, or execute arbitrary server-side logic.",
            "recommended_remediation": "Never construct template source strings from user input; always pass user values strictly as data variables to pre-compiled templates.",
            "secure_guidance": "In Jinja2/Mako/Handlebars, use `render_template('view.html', query=user_input)` instead of `Template(user_input).render()`, and enable strict template sandboxing where dynamic expressions are required.",
            "verification": "Submit harmless mathematical template probes (e.g., `{{7*191}}` or `${7*191}`) and verify the literal string is returned un-evaluated.",
            "owasp": ["A03:2021 - Injection"],
            "prereqs": ["Audit all dynamic template string rendering calls across backend handlers"],
        },
        "CWE-918": {
            "root_cause": "Server-side HTTP client accepts a user-supplied URL or hostname without allowlist validation or private-network egress blocking.",
            "why_it_matters": "Allows attackers to pivot through the server to probe internal services, private RFC 1918 subnets, or cloud instance metadata endpoints.",
            "recommended_remediation": "Validate target destinations against an explicit domain allowlist, resolve DNS prior to socket creation, and block private/loopback/link-local/metadata IP ranges.",
            "secure_guidance": "Implement an egress validation gate blocking RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), `127.0.0.0/8`, `169.254.0.0/16`, and disable HTTP redirects on server-side fetches.",
            "verification": "Verify server rejects URLs targeting loopback (`127.0.0.1`), metadata (`169.254.169.254`), and unapproved external hosts with HTTP 400/403.",
            "owasp": ["A10:2021 - Server-Side Request Forgery (SSRF)"],
            "prereqs": ["Inventory outbound webhook, avatar fetch, and proxy endpoints"],
        },
        "CWE-611": {
            "root_cause": "XML parser processes Document Type Definitions (DTDs) and external entity declarations from untrusted XML payloads.",
            "why_it_matters": "Permits local file disclosure, SSRF against internal endpoints, or entity expansion denial-of-service (Billion Laughs).",
            "recommended_remediation": "Disable DTD processing and external entity resolution in all XML parser configurations.",
            "secure_guidance": "In Python use `defusedxml` instead of `xml.etree.ElementTree`/`lxml` defaults (`resolve_entities=False`, `no_network=True`, `dtd_validation=False`). Prefer JSON over XML APIs.",
            "verification": "Send a safe internal entity definition probe and confirm parser rejects DTD declarations cleanly.",
            "owasp": ["A05:2021 - Security Misconfiguration"],
            "prereqs": ["Identify all XML/SOAP/SVG ingestion endpoints"],
        },
        "CWE-601": {
            "root_cause": "Application redirects users to a URL read from an unvalidated query or body parameter.",
            "why_it_matters": "Facilitates credential phishing campaigns abusing trusted application domains and can bypass OAuth `redirect_uri` checks.",
            "recommended_remediation": "Restrict redirects to relative internal paths or validate destinations against an explicit allowlist of trusted origins.",
            "secure_guidance": "Parse destination with `urlparse()`, verify `scheme == '' and netloc == ''` for relative paths, or match `netloc` strictly against a fixed allowlist.",
            "verification": "Send `https://example.invalid` to the redirect parameter and verify the server does not return a `3xx Location: https://example.invalid` header.",
            "owasp": ["A01:2021 - Broken Access Control"],
            "prereqs": ["Audit login, logout, and SSO callback return URL parameters"],
        },
        "CWE-693": {
            "root_cause": "HTTP responses lack defensive browser security headers (such as Content-Security-Policy, HSTS, X-Content-Type-Options, or Referrer-Policy).",
            "why_it_matters": "Missing hardening headers remove defense-in-depth protections against XSS execution, MIME-sniffing, and protocol downgrade attacks.",
            "recommended_remediation": "Configure web server or ASGI/reverse-proxy middleware to emit standard security headers on all HTTP responses.",
            "secure_guidance": "Set `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy`, and a non-trivial `Content-Security-Policy`.",
            "verification": "Execute a passive `HEAD`/`GET` request and confirm all required security headers appear in response headers.",
            "owasp": ["A05:2021 - Security Misconfiguration"],
            "prereqs": ["Verify third-party script/frame origins before enforcing strict CSP"],
        },
        "CWE-1021": {
            "root_cause": "Response omits clickjacking frame protections (`X-Frame-Options` or CSP `frame-ancestors`).",
            "why_it_matters": "Allows malicious third-party sites to embed application pages in hidden iframes to trick authenticated users into unintended clicks.",
            "recommended_remediation": "Add `Content-Security-Policy: frame-ancestors 'self'` (or `'none'`) and `X-Frame-Options: DENY` or `SAMEORIGIN`.",
            "secure_guidance": "Configure middleware headers uniformly across HTML responses so framing is explicitly restricted.",
            "verification": "Inspect response headers via `curl -I` and verify `X-Frame-Options` or `frame-ancestors` directive is present.",
            "owasp": ["A04:2021 - Insecure Design", "A05:2021 - Security Misconfiguration"],
            "prereqs": ["Confirm whether legitimate widgets require iframe embedding"],
        },
        "CWE-614": {
            "root_cause": "Sensitive cookies are issued without the `Secure`, `HttpOnly`, or strict `SameSite` flags.",
            "why_it_matters": "Allows session cookies to be transmitted over cleartext HTTP, read by client-side scripts during XSS, or sent in cross-site requests.",
            "recommended_remediation": "Set `Secure; HttpOnly; SameSite=Lax` (or `Strict`) on all session and authentication `Set-Cookie` headers.",
            "secure_guidance": "Update framework cookie/session middleware configuration (`SESSION_COOKIE_SECURE=True`, `SESSION_COOKIE_HTTPONLY=True`, `SESSION_COOKIE_SAMESITE='Lax'`).",
            "verification": "Inspect `Set-Cookie` headers during login/session creation to confirm security attributes are present.",
            "owasp": ["A05:2021 - Security Misconfiguration", "A07:2021 - Identification and Authentication Failures"],
            "prereqs": ["Ensure application runs over HTTPS in staging/production before enabling `Secure`"],
        },
        "CWE-1004": {
            "root_cause": "Session cookie omits the `HttpOnly` attribute, leaving it readable via `document.cookie`.",
            "why_it_matters": "Any cross-site scripting flaw immediately enables trivial session token exfiltration.",
            "recommended_remediation": "Add the `HttpOnly` flag to all session-bearing `Set-Cookie` headers.",
            "secure_guidance": "Configure `httponly=True` on cookie setters in FastAPI/Starlette/Express response handlers.",
            "verification": "Verify `HttpOnly` appears in `Set-Cookie` response header.",
            "owasp": ["A05:2021 - Security Misconfiguration"],
            "prereqs": ["Ensure frontend JS does not intentionally read session cookie values"],
        },
        "CWE-942": {
            "root_cause": "Cross-Origin Resource Sharing (`Access-Control-Allow-Origin`) uses overly permissive wildcard or unchecked origin reflection.",
            "why_it_matters": "Permits untrusted external origins to read authenticated API responses from victim browsers.",
            "recommended_remediation": "Validate the `Origin` header against a strict explicit allowlist and avoid combining wildcard origins with `Access-Control-Allow-Credentials: true`.",
            "secure_guidance": "Configure `CORSMiddleware(allow_origins=['https://app.example.com'])` instead of dynamic reflection or `*`.",
            "verification": "Send a request with `Origin: https://untrusted.invalid` and confirm it is not echoed in `Access-Control-Allow-Origin`.",
            "owasp": ["A05:2021 - Security Misconfiguration"],
            "prereqs": ["Catalog legitimate frontend origins consuming the API"],
        },
        "CWE-200": {
            "root_cause": "HTTP headers, error traces, or endpoints disclose internal software versions, stack frames, or sensitive metadata.",
            "why_it_matters": "Reveals exact server versions and internal architecture details that simplify targeted exploitation.",
            "recommended_remediation": "Suppress `Server`, `X-Powered-By`, and framework version headers, and disable verbose debug error pages in production.",
            "secure_guidance": "In Nginx set `server_tokens off;`; in Express set `app.disable('x-powered-by')`; return generic error payloads in FastAPI exception handlers.",
            "verification": "Inspect response headers and trigger a benign 404/400 request to ensure no version banners or stack traces appear.",
            "owasp": ["A01:2021 - Broken Access Control", "A05:2021 - Security Misconfiguration"],
            "prereqs": ["Ensure structured server-side logging captures errors internally without returning them to clients"],
        },
        "CWE-319": {
            "root_cause": "Endpoint serves content or accepts sensitive submissions over unencrypted HTTP transport.",
            "why_it_matters": "Network observers can intercept credentials, session cookies, and application data in cleartext.",
            "recommended_remediation": "Enforce HTTPS across all endpoints, redirect HTTP to HTTPS, and deploy `Strict-Transport-Security` (HSTS).",
            "secure_guidance": "Terminate TLS 1.2/1.3 at the edge proxy and emit `Strict-Transport-Security: max-age=31536000; includeSubDomains`.",
            "verification": "Verify plain HTTP requests receive a 301/308 redirect to `https://` and HSTS header is present.",
            "owasp": ["A02:2021 - Cryptographic Failures"],
            "prereqs": ["Valid TLS certificate provisioned for target domain"],
        },
        "CWE-352": {
            "root_cause": "State-changing form or endpoint lacks anti-CSRF token validation or strict SameSite cookie enforcement.",
            "why_it_matters": "Third-party sites can forge authenticated requests on behalf of logged-in victims.",
            "recommended_remediation": "Require cryptographically random, per-session anti-CSRF tokens validated server-side on all state-changing requests.",
            "secure_guidance": "Implement synchronizer token or double-submit cookie verification alongside `SameSite=Lax` cookies.",
            "verification": "Submit the form without or with an altered CSRF token and confirm the server rejects the request with HTTP 403.",
            "owasp": ["A01:2021 - Broken Access Control"],
            "prereqs": ["Audit state-mutating POST/PUT/DELETE forms and endpoints"],
        },
    }

    PRIORITY_MAP: Dict[ContextualPriority, RemediationPriority] = {
        ContextualPriority.CRITICAL: RemediationPriority.P0_IMMEDIATE,
        ContextualPriority.HIGH: RemediationPriority.P1_URGENT,
        ContextualPriority.MEDIUM: RemediationPriority.P2_SCHEDULED,
        ContextualPriority.LOW: RemediationPriority.P3_HARDENING,
        ContextualPriority.INFO: RemediationPriority.P3_HARDENING,
    }

    @classmethod
    def generate(
        cls,
        finding: NormalizedFinding,
        contextual_risk: ContextualRiskAssessmentSchema,
        existing_status: RemediationStatus = RemediationStatus.OPEN,
    ) -> RemediationIntelligenceSchema:
        """Produces structured, component-specific remediation intelligence."""
        kb = cls.KNOWLEDGE_BASE.get(finding.cwe_id)
        param_desc = f" (parameter `{finding.affected_parameter}`)" if finding.affected_parameter else ""
        tech_desc = f" | Stack: {', '.join(finding.technology_relationships[:3])}" if finding.technology_relationships else ""
        affected_component = f"{finding.http_method} {finding.endpoint_path}{param_desc}{tech_desc}"

        priority = cls.PRIORITY_MAP.get(contextual_risk.contextual_priority, RemediationPriority.P2_SCHEDULED)
        cwe_refs = [finding.cwe_id] if finding.cwe_id and finding.cwe_id != "CWE-0" else []

        if kb:
            owasp_refs = [finding.owasp_category] if finding.owasp_category else list(kb["owasp"])
            guidance = kb["secure_guidance"]
            if finding.technology_relationships:
                guidance += f" Observed technologies for review: {', '.join(finding.technology_relationships[:4])}."
            return RemediationIntelligenceSchema(
                root_cause=kb["root_cause"],
                why_it_matters=kb["why_it_matters"],
                affected_component=affected_component,
                recommended_remediation=finding.remediation_text or kb["recommended_remediation"],
                secure_implementation_guidance=guidance,
                verification_guidance=kb["verification"],
                cwe_references=cwe_refs,
                owasp_references=owasp_refs,
                remediation_priority=priority,
                remediation_status=existing_status,
                prerequisites=list(kb["prereqs"]),
            )

        # Deterministic safe fallback tailored to actual finding metadata (zero fabricated CVEs/links)
        owasp_refs = [finding.owasp_category] if finding.owasp_category else ["A05:2021 - Security Misconfiguration"]
        rec = finding.remediation_text or f"Review and remediate {finding.vulnerability_category.lower().replace('_', ' ')} control on {affected_component}."
        return RemediationIntelligenceSchema(
            root_cause=f"Security weakness detected under category {finding.vulnerability_category} ({finding.cwe_id}) on {finding.endpoint_path}.",
            why_it_matters=f"Exposure on {affected_component} may degrade application confidentiality, integrity, or security posture ({finding.severity.value} severity).",
            affected_component=affected_component,
            recommended_remediation=rec,
            secure_implementation_guidance=f"Apply defensive input validation, strict configuration hardening, and principle of least privilege for {affected_component}.",
            verification_guidance=f"Re-scan endpoint `{finding.normalized_endpoint}` with Ashlynx safe validation after deploying configuration or code fix.",
            cwe_references=cwe_refs,
            owasp_references=owasp_refs,
            remediation_priority=priority,
            remediation_status=existing_status,
            prerequisites=["Code/configuration owner review of affected endpoint", "Regression test coverage before deployment"],
        )
