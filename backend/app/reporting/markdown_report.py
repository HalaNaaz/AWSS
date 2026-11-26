from shared.schemas.report import ReportFormat, UnifiedScanReport
from backend.app.reporting.base import BaseReportGenerator
from backend.app.scanner.evidence.redactor import EvidenceRedactor


class MarkdownReportGenerator(BaseReportGenerator):
    """Generates human-readable GitHub-flavored Markdown security reports."""

    @property
    def format_name(self) -> ReportFormat:
        return ReportFormat.MARKDOWN

    @property
    def content_type(self) -> str:
        return "text/markdown; charset=utf-8"

    def generate(self, report: UnifiedScanReport) -> str:
        lines = []

        # Header
        lines.append(f"# Ashlynx WebSec Scanner Assessment Report")
        lines.append(f"**Target URL:** `{report.target_url}`  ")
        lines.append(f"**Scan ID:** `{report.scan_id}`  ")
        lines.append(f"**Scan Profile:** `{report.profile.value}`  ")
        lines.append(f"**Execution Status:** `{report.status.value}`  ")
        lines.append(f"**Generated At:** `{report.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}`  ")
        lines.append(f"**Duration:** `{report.duration_seconds}s`  ")
        lines.append("")
        lines.append("---")
        lines.append("")

        # Executive Summary
        lines.append("## 1. Executive Summary")
        lines.append(
            f"Ashlynx WebSec Scanner completed an automated dynamic security assessment of **{report.target_url}**. "
            f"During the reconnaissance and analysis workflow, the scanner crawled **{report.urls_crawled}** URLs, "
            f"identified **{report.endpoints_discovered}** endpoints, **{report.forms_discovered}** HTML forms, "
            f"and detected **{len(report.technologies)}** framework/server technologies."
        )
        lines.append("")

        # Severity Summary Table
        s = report.severity_summary
        lines.append("### Vulnerability Severity Breakdown")
        lines.append("")
        lines.append("| Severity | Count | Risk Level |")
        lines.append("| :--- | :---: | :--- |")
        lines.append(f"| **CRITICAL** | {s.critical} | Immediate remediation required |")
        lines.append(f"| **HIGH** | {s.high} | Elevated security risk |")
        lines.append(f"| **MEDIUM** | {s.medium} | Moderate vulnerability or misconfiguration |")
        lines.append(f"| **LOW** | {s.low} | Minor security deficiency |")
        lines.append(f"| **INFORMATIONAL** | {s.informational} | Diagnostic and hardening observation |")
        lines.append(f"| **TOTAL** | **{s.total}** | **All detected issues** |")
        lines.append("")

        # Technology Inventory
        if report.technologies:
            lines.append("## 2. Detected Technology Stack")
            lines.append("")
            lines.append("| Technology | Category | Version | Confidence | Source |")
            lines.append("| :--- | :--- | :--- | :---: | :--- |")
            for t in report.technologies:
                lines.append(f"| {t.technology_name} | {t.category} | {t.version or '-'} | {int(t.confidence * 100)}% | {t.detection_source} |")
            lines.append("")

        # Detailed Findings Section
        lines.append("## 3. Security Findings & Remediation Guidance")
        lines.append("")

        if not report.findings:
            lines.append("✓ **No vulnerabilities or security misconfigurations were identified during this assessment.**")
            lines.append("")
        else:
            for idx, f in enumerate(report.findings, start=1):
                sev_badge = f"[{f.severity.value}]"
                lines.append(f"### 3.{idx} {f.title} {sev_badge}")
                lines.append(f"- **Vulnerability ID / Rule:** `{f.id}`")
                lines.append(f"- **Affected Endpoint:** `{EvidenceRedactor.redact(f.endpoint.url)}`")
                lines.append(f"- **HTTP Method:** `{f.endpoint.method}`" + (f" (Param: `{f.endpoint.parameter}`)" if f.endpoint.parameter else ""))
                lines.append(f"- **Severity:** **{f.severity.value}** (CVSS: {f.cvss_score})")
                lines.append(f"- **Classification:** CWE-{f.cwe_id.replace('CWE-', '')}" + (f" | {f.owasp_category}" if f.owasp_category else ""))
                if f.intelligence:
                    intel = f.intelligence
                    lines.append(
                        f"- **AVIVE Confidence:** **{intel.confidence_assessment.level.value}** ({int(intel.confidence_assessment.score * 100)}%) | "
                        f"**Validation State:** `{intel.validation_state.value}` | "
                        f"**Contextual Priority:** `{intel.contextual_risk.contextual_priority.value}` ({intel.contextual_risk.contextual_score}/100)"
                    )
                    if intel.correlation_group_id:
                        lines.append(
                            f"- **Correlation Group:** `{intel.correlation_group_id}` ({intel.correlation_relationship.value}"
                            + (", Duplicate" if intel.is_duplicate else ", Primary")
                            + ")"
                        )
                else:
                    lines.append(f"- **Confidence:** {int(f.confidence * 100)}% | **Status:** `{f.status.value}`")
                lines.append("")
                lines.append(f"**Description:**  ")
                lines.append(f"{f.description}")
                lines.append("")

                if f.intelligence and f.intelligence.remediation_intelligence:
                    rem = f.intelligence.remediation_intelligence
                    lines.append(f"**Root Cause:** {rem.root_cause}  ")
                    lines.append(f"**Remediation Recommendation ({rem.remediation_priority.value}):** {rem.recommended_remediation}  ")
                    lines.append(f"**Secure Implementation Guidance:** {rem.secure_implementation_guidance}  ")
                    lines.append(f"**Verification Guidance:** {rem.verification_guidance}")
                    lines.append("")
                elif f.remediation:
                    lines.append(f"**Remediation Recommendation:**  ")
                    lines.append(f"{f.remediation}")
                    lines.append("")

                if f.evidence:
                    lines.append("**Cryptographic Evidence (Redacted):**")
                    lines.append(f"- **SHA-256 Integrity Seal:** `{f.evidence.sha256_hash}`")
                    if f.evidence.response:
                        lines.append("```http")
                        lines.append(EvidenceRedactor.redact(f.evidence.response.strip()))
                        lines.append("```")
                        lines.append("")

                lines.append("---")
                lines.append("")

        if report.security_coverage:
            cov = report.security_coverage
            lines.append("## 4. OWASP Top 10:2021 Security Coverage Intelligence")
            lines.append(
                f"**Overall DAST Coverage:** `{cov.overall_dast_coverage_percent}%` "
                f"(Tested: {cov.tested_categories_count}, Partial: {cov.partial_categories_count}, "
                f"Skipped: {cov.skipped_categories_count}, Untested: {cov.untested_categories_count})"
            )
            lines.append("")
            lines.append("| OWASP Category | Status | Findings | Explanation |")
            lines.append("| :--- | :--- | :---: | :--- |")
            for entry in cov.owasp_categories:
                lines.append(f"| {entry.owasp_id} {entry.owasp_name} | `{entry.status.value}` | {entry.findings_detected} | {entry.explanation} |")
            lines.append("")
            lines.append(f"*{cov.honesty_disclaimer}*")
            lines.append("")

        return "\n".join(lines)
