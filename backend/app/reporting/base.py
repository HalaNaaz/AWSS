from abc import ABC, abstractmethod
from shared.schemas.report import ReportFormat, UnifiedScanReport


class BaseReportGenerator(ABC):
    """Abstract base class for all scan report format exporters."""

    @property
    @abstractmethod
    def format_name(self) -> ReportFormat:
        """The ReportFormat identifier handled by this generator."""
        pass

    @property
    @abstractmethod
    def content_type(self) -> str:
        """MIME type for HTTP transmission, e.g. 'text/html' or 'application/json'."""
        pass

    @abstractmethod
    def generate(self, report: UnifiedScanReport) -> str:
        """Generates formatted report content string from unified scan telemetry.
        
        Args:
            report: Populated UnifiedScanReport entity.
            
        Returns:
            Rendered string representation of the report.
        """
        pass
