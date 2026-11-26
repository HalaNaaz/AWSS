import urllib.parse
from typing import List
from uuid import UUID

from shared.schemas.common import Severity, FindingStatus
from backend.app.scanner.active.base import BaseActiveAnalyzer
from backend.app.scanner.active.models import ActiveTarget, ActiveFinding, RequestBudgetTracker
from backend.app.scanner.crawler.client import AsyncHTTPClient
from backend.app.scanner.evidence.redactor import EvidenceRedactor


class APISecurityAnalyzer(BaseActiveAnalyzer):
    """Non-destructive API Security & Access Control Indicator Analyzer.

    Checks:
    - Unauthenticated GraphQL Introspection enabled.
    - Unauthenticated OpenAPI/Swagger specification exposure.
    - Safe X-HTTP-Method-Override acceptance (using benign HEAD override).
    - API Content-Type confusion (JSON endpoint accepting text/plain).
    """

    SWAGGER_PATHS = ["/openapi.json", "/swagger.json", "/v3/api-docs"]
    GRAPHQL_PATHS = ["/graphql", "/api/graphql"]

    @property
    def analyzer_id(self) -> str:
        return "ACT-API-SEC-ANALYZER"

    @property
    def analyzer_name(self) -> str:
        return "API Security & Access Control Detector"

    @property
    def category(self) -> str:
        return "API Security"

    @property
    def supported_rules(self) -> List[str]:
        return [
            "ACT-API-GRAPHQL-INTROSPECTION",
            "ACT-API-SWAGGER-EXPOSED",
            "ACT-API-METHOD-OVERRIDE",
            "ACT-API-CONTENT-TYPE-CONFUSION",
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
        path_lower = (parsed.path or "/").lower()
        base_origin = f"{parsed.scheme}://{parsed.netloc}"
        is_root_or_api = path_lower in {"", "/", "/api", "/api/"} or "/api/" in path_lower

        # 1. GraphQL Introspection Check
        graphql_candidates = [target.url] if "graphql" in path_lower else (
            [f"{base_origin}{p}" for p in self.GRAPHQL_PATHS] if path_lower in {"", "/"} else []
        )
        for gql_url in graphql_candidates:
            if not budget.can_request():
                break
            budget.consume(1)
            try:
                resp, _ = await client.post(
                    gql_url,
                    json={"query": "{__schema{types{name}}}"},
                    headers={"Content-Type": "application/json"},
                )
                if not resp:
                    continue
                body = resp.text or ""
                if resp.status_code == 200 and '"__schema"' in body and '"types"' in body:
                    findings.append(
                        ActiveFinding(
                            rule_id="ACT-API-GRAPHQL-INTROSPECTION",
                            title="GraphQL Introspection Enabled Unauthenticated",
                            description=f"GraphQL endpoint '{gql_url}' responds to unauthenticated schema introspection queries.",
                            cwe_id="CWE-200",
                            owasp_category="A05:2021 - Security Misconfiguration",
                            severity=Severity.LOW,
                            cvss_score=3.7,
                            status=FindingStatus.VERIFIED,
                            confidence=0.95,
                            url=gql_url,
                            http_method="POST",
                            evidence_request=f"POST {gql_url} {{\"query\":\"{{__schema{{types{{name}}}}}}\"}}",
                            evidence_response=EvidenceRedactor.redact(body[:350]),
                            remediation="Disable GraphQL introspection in production environments or restrict it to authenticated internal roles.",
                            detection_module=self.analyzer_id,
                            probe_count=1,
                        )
                    )
                    break
            except Exception:
                continue

        # 2. OpenAPI / Swagger Specification Exposure on origin root
        if path_lower in {"", "/"}:
            for spec_path in self.SWAGGER_PATHS:
                if not budget.can_request():
                    break
                spec_url = f"{base_origin}{spec_path}"
                budget.consume(1)
                try:
                    resp, _ = await client.get(spec_url)
                    if not resp:
                        continue
                    body = resp.text or ""
                    if resp.status_code == 200 and ('"openapi"' in body or '"swagger"' in body) and '"paths"' in body:
                        findings.append(
                            ActiveFinding(
                                rule_id="ACT-API-SWAGGER-EXPOSED",
                                title=f"Unauthenticated OpenAPI/Swagger Specification Exposed ({spec_path})",
                                description=f"API schema specification is publicly accessible at '{spec_url}', mapping all internal endpoints and parameters.",
                                cwe_id="CWE-200",
                                owasp_category="A05:2021 - Security Misconfiguration",
                                severity=Severity.LOW,
                                cvss_score=3.7,
                                status=FindingStatus.VERIFIED,
                                confidence=0.95,
                                url=spec_url,
                                http_method="GET",
                                evidence_request=f"GET {spec_url}",
                                evidence_response=EvidenceRedactor.redact(body[:350]),
                                remediation="Restrict OpenAPI/Swagger documentation endpoints to authenticated developers or internal networks.",
                                detection_module=self.analyzer_id,
                                probe_count=1,
                            )
                        )
                        break
                except Exception:
                    continue

        # 3. Safe X-HTTP-Method-Override Acceptance (using benign HEAD override)
        if is_root_or_api and target.baseline_body and len(target.baseline_body) > 20 and budget.can_request():
            budget.consume(1)
            try:
                override_resp, _ = await client.get(
                    target.url,
                    headers={"X-HTTP-Method-Override": "HEAD"},
                )
                if override_resp and override_resp.status_code in {200, 204} and len(override_resp.text or "") == 0:
                    findings.append(
                        ActiveFinding(
                            rule_id="ACT-API-METHOD-OVERRIDE",
                            title="HTTP Method Override Header Honored (X-HTTP-Method-Override)",
                            description=(
                                f"Endpoint '{target.url}' honored 'X-HTTP-Method-Override: HEAD' on a GET request, "
                                f"indicating method-override processing that may bypass method-based access controls or WAF rules."
                            ),
                            cwe_id="CWE-650",
                            owasp_category="A01:2021 - Broken Access Control",
                            severity=Severity.LOW,
                            cvss_score=3.7,
                            status=FindingStatus.VERIFIED,
                            confidence=0.90,
                            url=target.url,
                            http_method="GET",
                            evidence_request=f"GET {target.url}\nX-HTTP-Method-Override: HEAD",
                            evidence_response=f"HTTP {override_resp.status_code} (empty HEAD body returned)",
                            remediation="Disable X-HTTP-Method-Override / X-Method-Override header processing unless strictly required, and enforce authorization after method resolution.",
                            detection_module=self.analyzer_id,
                            probe_count=1,
                        )
                    )
            except Exception:
                pass

        # 4. Content-Type Confusion on API JSON endpoints
        is_json_api = "/api/" in path_lower or "application/json" in (target.content_type or "").lower()
        if is_json_api and target.method.upper() in {"POST", "PUT", "PATCH"} and budget.can_request():
            budget.consume(1)
            try:
                ct_resp, _ = await client.post(
                    target.url,
                    content=b'{"ashlynx_ct_probe":1}',
                    headers={"Content-Type": "text/plain"},
                )
                if ct_resp and ct_resp.status_code in {200, 201}:
                    findings.append(
                        ActiveFinding(
                            rule_id="ACT-API-CONTENT-TYPE-CONFUSION",
                            title="API Endpoint Accepts 'text/plain' Without 415 Enforcement",
                            description=(
                                f"API endpoint '{target.url}' returned HTTP {ct_resp.status_code} for a POST body with 'Content-Type: text/plain', "
                                f"which can weaken CSRF/CORS preflight protections if JSON parsing occurs."
                            ),
                            cwe_id="CWE-436",
                            owasp_category="A05:2021 - Security Misconfiguration",
                            severity=Severity.LOW,
                            cvss_score=3.5,
                            status=FindingStatus.SUSPECTED,
                            confidence=0.62,
                            url=target.url,
                            http_method="POST",
                            evidence_request=f"POST {target.url} (Content-Type: text/plain)",
                            evidence_response=EvidenceRedactor.redact((ct_resp.text or "")[:300]),
                            remediation="Strictly require 'Content-Type: application/json' on JSON API endpoints and return HTTP 415 Unsupported Media Type otherwise.",
                            detection_module=self.analyzer_id,
                            probe_count=1,
                        )
                    )
            except Exception:
                pass

        return findings
