from shared.schemas.report import ReportFormat, UnifiedScanReport
from backend.app.reporting.base import BaseReportGenerator
from backend.app.scanner.evidence.redactor import EvidenceRedactor


class JSONReportGenerator(BaseReportGenerator):
    """Generates structured machine-readable JSON security reports."""

    @property
    def format_name(self) -> ReportFormat:
        return ReportFormat.JSON

    @property
    def content_type(self) -> str:
        return "application/json; charset=utf-8"

    def generate(self, report: UnifiedScanReport) -> str:
        sanitized = report.model_copy(deep=True)
        for finding in sanitized.findings:
            finding.endpoint.url = EvidenceRedactor.redact(finding.endpoint.url)
            if finding.curl_reproduction:
                finding.curl_reproduction = EvidenceRedactor.redact(finding.curl_reproduction)
            if finding.evidence:
                finding.evidence.request = EvidenceRedactor.redact(finding.evidence.request)
                finding.evidence.response = EvidenceRedactor.redact(finding.evidence.response)
        return sanitized.model_dump_json(indent=2)
