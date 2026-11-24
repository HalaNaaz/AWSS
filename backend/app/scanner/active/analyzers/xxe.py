from typing import List
from uuid import UUID

from shared.schemas.common import Severity, FindingStatus
from backend.app.scanner.active.base import BaseActiveAnalyzer
from backend.app.scanner.active.models import ActiveTarget, ActiveFinding, RequestBudgetTracker
from backend.app.scanner.crawler.client import AsyncHTTPClient


class XXEAnalyzer(BaseActiveAnalyzer):
    """Safe XML External Entity (XXE) and XML Parser Configuration Analyzer.
    
    Checks if XML endpoints process custom DTD entities and expand them in responses.
    
    Safety Guarantee:
    - Never uses SYSTEM identifiers referencing local files (file://, C:\\).
    - Never references external network resources (http://).
    - Uses purely benign, local inline entity definitions with randomized text canaries.
    """

    BENIGN_CANARY = "ASHLYNX_BENIGN_XXE_CANARY_TEST_MARKER"

    @property
    def analyzer_id(self) -> str:
        return "ACT-XXE-ANALYZER"

    @property
    def analyzer_name(self) -> str:
        return "Safe XML Parser Configuration Detector"

    @property
    def category(self) -> str:
        return "XML External Entity"

    @property
    def supported_rules(self) -> List[str]:
        return ["ACT-XXE-ENTITY-EXPANSION"]

    async def check(
        self,
        target: ActiveTarget,
        client: AsyncHTTPClient,
        budget: RequestBudgetTracker,
        scan_id: UUID,
    ) -> List[ActiveFinding]:
        findings: List[ActiveFinding] = []

        # Only target endpoints that indicate XML ingestion or POST endpoints with XML in headers
        is_xml_endpoint = (
            "xml" in target.url.lower()
            or "xml" in (target.content_type or "").lower()
            or target.method == "POST"
        )
        if not is_xml_endpoint or not budget.can_request():
            return findings

        # Safe, inert XML payload with local internal entity expansion (no external resolution)
        safe_xml_payload = (
            f'<?xml version="1.0" encoding="UTF-8"?>\r\n'
            f'<!DOCTYPE root [ <!ENTITY canary "{self.BENIGN_CANARY}"> ]>\r\n'
            f'<root><data>&canary;</data></root>'
        )

        headers = {
            "Content-Type": "application/xml",
            "Accept": "application/xml, text/xml, */*",
        }

        budget.consume(1)
        resp, _ = await client.request(
            method="POST",
            url=target.url,
            headers=headers,
            content=safe_xml_payload.encode("utf-8"),
        )

        if resp and resp.text:
            if self.BENIGN_CANARY in resp.text:
                # Entity expansion confirmed in server-side XML parser
                finding = ActiveFinding(
                    rule_id="ACT-XXE-ENTITY-EXPANSION",
                    title="XML Parser Custom Entity Expansion Enabled",
                    description=(
                        f"The XML parser on endpoint '{target.url}' processed a custom local DTD entity definition "
                        f"and expanded the entity in its response. Insecure XML parsers without entity resolution controls "
                        f"are susceptible to XML External Entity (XXE) and XML bomb attacks."
                    ),
                    cwe_id="CWE-611",
                    owasp_category="A05:2021 - Security Misconfiguration",
                    severity=Severity.HIGH,
                    cvss_score=8.2,
                    status=FindingStatus.VERIFIED,
                    confidence=0.95,
                    url=target.url,
                    http_method="POST",
                    evidence_request=safe_xml_payload,
                    evidence_response=resp.text[:300],
                    remediation="Disable external DTD resolution and general entity expansion in the XML parser (e.g. setFeature('http://apache.org/xml/features/disallow-doctype-decl', true)).",
                    detection_module=self.analyzer_id,
                    probe_count=1,
                )
                findings.append(finding)

        return findings
