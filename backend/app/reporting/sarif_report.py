import json
import re
from typing import Any, Dict, List
from shared.schemas.common import ScanStatus, Severity
from shared.schemas.report import ReportFormat, UnifiedScanReport
from backend.app.reporting.base import BaseReportGenerator


_SARIF_LEVEL_MAP: Dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFORMATIONAL: "note",
}


def _slugify_rule_id(cwe_id: str, title: str) -> str:
    """Produces a stable SARIF ruleId from CWE identifier and finding title."""
    cwe_part = re.sub(r"[^A-Za-z0-9]+", "", cwe_id.upper()) or "AWSS"
    title_slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")[:48]
    return f"{cwe_part}-{title_slug}" if title_slug else cwe_part


class SARIFReportGenerator(BaseReportGenerator):
    """Generates OASIS SARIF 2.1.0 JSON reports for CI/CD and code-scanning integration."""

    SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"

    @property
    def format_name(self) -> ReportFormat:
        return ReportFormat.SARIF

    @property
    def content_type(self) -> str:
        return "application/sarif+json; charset=utf-8"

    def generate(self, report: UnifiedScanReport) -> str:
        rules_by_id: Dict[str, Dict[str, Any]] = {}
        results: List[Dict[str, Any]] = []

        for finding in report.findings:
            rule_id = _slugify_rule_id(finding.cwe_id, finding.title)
            level = _SARIF_LEVEL_MAP.get(finding.severity, "warning")

            if rule_id not in rules_by_id:
                tags = ["security", finding.cwe_id]
                if finding.owasp_category:
                    tags.append(finding.owasp_category)

                rules_by_id[rule_id] = {
                    "id": rule_id,
                    "name": finding.title,
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": finding.description or finding.title},
                    "defaultConfiguration": {"level": level},
                    "help": {
                        "text": finding.remediation
                        or f"Review and remediate {finding.cwe_id} on the affected endpoint."
                    },
                    "properties": {
                        "tags": tags,
                        "security-severity": f"{finding.cvss_score:.1f}",
                        "cwe": finding.cwe_id,
                    },
                }

            message_parts = [finding.title]
            if finding.description:
                message_parts.append(finding.description)
            message_parts.append(f"[Status: {finding.status.value} | Severity: {finding.severity.value}]")

            location: Dict[str, Any] = {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.endpoint.url}
                }
            }
            if finding.endpoint.parameter:
                location["logicalLocations"] = [
                    {
                        "name": finding.endpoint.parameter,
                        "kind": "parameter",
                        "fullyQualifiedName": f"{finding.endpoint.method} {finding.endpoint.url} ({finding.endpoint.parameter})",
                    }
                ]

            result_entry: Dict[str, Any] = {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": " - ".join(message_parts)},
                "locations": [location],
                "properties": {
                    "finding_id": str(finding.id),
                    "severity": finding.severity.value,
                    "cvss_score": finding.cvss_score,
                    "cwe_id": finding.cwe_id,
                    "owasp_category": finding.owasp_category,
                    "status": finding.status.value,
                    "confidence": finding.confidence,
                    "method": finding.endpoint.method,
                    "parameter": finding.endpoint.parameter,
                },
            }

            if finding.evidence and finding.evidence.sha256_hash:
                result_entry["partialFingerprints"] = {
                    "evidenceSha256": finding.evidence.sha256_hash
                }

            results.append(result_entry)

        invocation: Dict[str, Any] = {
            "executionSuccessful": report.status != ScanStatus.FAILED,
            "properties": {
                "scan_id": str(report.scan_id),
                "target_url": report.target_url,
                "profile": report.profile.value,
                "status": report.status.value,
                "urls_crawled": report.urls_crawled,
                "endpoints_discovered": report.endpoints_discovered,
            },
        }
        if report.started_at:
            invocation["startTimeUtc"] = report.started_at.isoformat()
        if report.completed_at:
            invocation["endTimeUtc"] = report.completed_at.isoformat()

        sarif_doc: Dict[str, Any] = {
            "$schema": self.SCHEMA_URI,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Ashlynx WebSec Scanner",
                            "semanticVersion": "0.1.0",
                            "informationUri": "https://github.com/HalaNaaz/AWSS",
                            "rules": list(rules_by_id.values()),
                        }
                    },
                    "invocations": [invocation],
                    "results": results,
                }
            ],
        }
        return json.dumps(sarif_doc, indent=2)
