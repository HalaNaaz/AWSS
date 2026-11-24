from shared.schemas.report import ReportFormat, UnifiedScanReport
from backend.app.reporting.base import BaseReportGenerator


class JSONReportGenerator(BaseReportGenerator):
    """Generates structured machine-readable JSON security reports."""

    @property
    def format_name(self) -> ReportFormat:
        return ReportFormat.JSON

    @property
    def content_type(self) -> str:
        return "application/json; charset=utf-8"

    def generate(self, report: UnifiedScanReport) -> str:
        return report.model_dump_json(indent=2)
