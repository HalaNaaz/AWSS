import re
import urllib.parse
from typing import Dict, List, Tuple
from uuid import UUID

from shared.schemas.common import Severity, FindingStatus
from backend.app.scanner.active.base import BaseActiveAnalyzer
from backend.app.scanner.active.models import ActiveTarget, ActiveFinding, RequestBudgetTracker
from backend.app.scanner.crawler.client import AsyncHTTPClient
from backend.app.scanner.evidence.redactor import EvidenceRedactor


class PathTraversalAnalyzer(BaseActiveAnalyzer):
    """Non-destructive Two-Phase Path Traversal / LFI Indicator Analyzer.

    Probes file/path/template-like parameters using benign traversal probes
    paired with a negative control probe to eliminate false positives.
    """

    FILE_PARAM_PATTERN = re.compile(
        r"^(?:file|filename|filepath|path|page|template|tpl|doc|document|include|inc|view|dir|download|asset|lang|locale)$",
        re.IGNORECASE,
    )

    TRAVERSAL_PROBES: List[Tuple[str, List[str], str]] = [
        ("../../../../etc/passwd", ["root:x:0:0:", "daemon:x:", "/bin/bash", "/bin/sh"], "Unix /etc/passwd"),
        ("..\\..\\..\\..\\windows\\win.ini", ["[extensions]", "[fonts]", "[mci extensions]"], "Windows win.ini"),
    ]

    ERROR_INDICATORS = [
        "no such file or directory",
        "failed to open stream",
        "filenotfoundexception",
        "java.io.filenotfoundexception",
        "include_path",
    ]

    @property
    def analyzer_id(self) -> str:
        return "ACT-TRAVERSAL-ANALYZER"

    @property
    def analyzer_name(self) -> str:
        return "Path Traversal & LFI Indicator Detector"

    @property
    def category(self) -> str:
        return "Path Traversal"

    @property
    def supported_rules(self) -> List[str]:
        return ["ACT-TRAVERSAL-LFI"]

    @staticmethod
    def _build_url_with_param(base_url: str, param: str, value: str) -> str:
        parsed = urllib.parse.urlparse(base_url)
        query = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
        query[param] = value
        new_query = urllib.parse.urlencode(query)
        return urllib.parse.urlunparse(parsed._replace(query=new_query))

    async def check(
        self,
        target: ActiveTarget,
        client: AsyncHTTPClient,
        budget: RequestBudgetTracker,
        scan_id: UUID,
    ) -> List[ActiveFinding]:
        findings: List[ActiveFinding] = []
        candidate_params: Dict[str, str] = {
            k: v for k, v in target.parameters.items() if self.FILE_PARAM_PATTERN.match(k)
        }
        if not candidate_params:
            return findings

        baseline_lower = (target.baseline_body or "").lower()

        for param_name in list(candidate_params.keys())[:3]:
            if not budget.can_request():
                break

            # Negative control probe to verify dynamic file handling vs static page
            control_url = self._build_url_with_param(target.url, param_name, "ashlynx_nonexistent_7a9c3b.txt")
            budget.consume(1)
            try:
                control_resp = await client.get(control_url, scan_id=str(scan_id))
                control_body_lower = (control_resp.text or "").lower()
            except Exception:
                control_body_lower = ""

            for payload, markers, os_label in self.TRAVERSAL_PROBES:
                if not budget.can_request():
                    break
                probe_url = self._build_url_with_param(target.url, param_name, payload)
                budget.consume(1)
                try:
                    resp = await client.get(probe_url, scan_id=str(scan_id))
                except Exception:
                    continue

                body_text = resp.text or ""
                body_lower = body_text.lower()

                matched_marker = next(
                    (m for m in markers if m.lower() in body_lower and m.lower() not in baseline_lower and m.lower() not in control_body_lower),
                    None,
                )
                if matched_marker:
                    findings.append(
                        ActiveFinding(
                            rule_id="ACT-TRAVERSAL-LFI",
                            title=f"Path Traversal / Local File Inclusion Verified on '{param_name}'",
                            description=(
                                f"Parameter '{param_name}' on '{target.url}' returned {os_label} content marker "
                                f"'{matched_marker}' when probed with a relative traversal sequence, absent from baseline and negative control responses."
                            ),
                            cwe_id="CWE-22",
                            owasp_category="A01:2021 - Broken Access Control",
                            severity=Severity.HIGH,
                            cvss_score=7.5,
                            status=FindingStatus.VERIFIED,
                            confidence=0.95,
                            url=target.url,
                            parameter=param_name,
                            http_method="GET",
                            evidence_request=EvidenceRedactor.redact(f"GET {probe_url}"),
                            evidence_response=EvidenceRedactor.redact(body_text[:400]),
                            remediation="Validate file identifiers against an allowlist or map indirect IDs server-side; canonicalize paths and enforce chroot/base-directory containment.",
                            detection_module=self.analyzer_id,
                            probe_count=2,
                        )
                    )
                    break

                matched_err = next(
                    (err for err in self.ERROR_INDICATORS if err in body_lower and err not in baseline_lower and err not in control_body_lower),
                    None,
                )
                if matched_err:
                    findings.append(
                        ActiveFinding(
                            rule_id="ACT-TRAVERSAL-LFI",
                            title=f"Potential Path Traversal / File Handling Error on '{param_name}'",
                            description=(
                                f"Parameter '{param_name}' on '{target.url}' triggered a filesystem error indicator "
                                f"('{matched_err}') on traversal input, requiring manual verification."
                            ),
                            cwe_id="CWE-22",
                            owasp_category="A01:2021 - Broken Access Control",
                            severity=Severity.MEDIUM,
                            cvss_score=5.3,
                            status=FindingStatus.SUSPECTED,
                            confidence=0.58,
                            url=target.url,
                            parameter=param_name,
                            http_method="GET",
                            evidence_request=EvidenceRedactor.redact(f"GET {probe_url}"),
                            evidence_response=EvidenceRedactor.redact(body_text[:400]),
                            remediation="Validate file paths strictly against an allowlist and suppress verbose filesystem exceptions.",
                            detection_module=self.analyzer_id,
                            probe_count=2,
                        )
                    )
                    break

        return findings
