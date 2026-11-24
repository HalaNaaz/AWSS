import os
from pathlib import Path
from typing import Dict, Union, Optional
from uuid import UUID

from shared.schemas.report import ReportFormat, UnifiedScanReport
from backend.app.reporting.base import BaseReportGenerator
from backend.app.reporting.json_report import JSONReportGenerator
from backend.app.reporting.markdown_report import MarkdownReportGenerator
from backend.app.reporting.html_report import HTMLReportGenerator
from backend.app.core.exceptions import ScanConfigurationError


class ReportManager:
    """Manages report format registration, generation, and safe filesystem exports."""

    def __init__(self):
        self._generators: Dict[ReportFormat, BaseReportGenerator] = {
            ReportFormat.JSON: JSONReportGenerator(),
            ReportFormat.HTML: HTMLReportGenerator(),
            ReportFormat.MARKDOWN: MarkdownReportGenerator(),
        }

    def register_generator(self, generator: BaseReportGenerator) -> None:
        """Registers a custom report format generator."""
        self._generators[generator.format_name] = generator

    def generate_report(self, report: UnifiedScanReport, format_type: ReportFormat) -> str:
        """Renders report into requested string format."""
        if format_type not in self._generators:
            raise ScanConfigurationError(f"Unsupported report format: '{format_type}'. Supported formats: {list(self._generators.keys())}")
        return self._generators[format_type].generate(report)

    def get_content_type(self, format_type: ReportFormat) -> str:
        """Returns HTTP content-type header for format."""
        if format_type in self._generators:
            return self._generators[format_type].content_type
        return "text/plain; charset=utf-8"

    @classmethod
    def validate_and_resolve_output_path(
        cls,
        output_path: Union[str, Path],
        allowed_root_dir: Optional[Path] = None
    ) -> Path:
        """Validates path against path traversal attacks and arbitrary system overwrites.
        
        Args:
            output_path: Target filename or path.
            allowed_root_dir: Optional root directory boundary.
            
        Returns:
            Resolved, validated absolute Path.
            
        Raises:
            ScanConfigurationError if path contains illegal sequences or escapes allowed boundaries.
        """
        path_obj = Path(output_path).resolve()
        
        # Check against path traversal components
        raw_str = str(output_path)
        if ".." in raw_str.split(os.sep) or ".." in raw_str.split("/"):
            raise ScanConfigurationError(f"Invalid output path: Path traversal sequence ('..') detected in '{output_path}'.")

        # Disallow prohibited system destinations on Windows / Unix
        prohibited_roots = [Path("C:\\Windows"), Path("/etc"), Path("/root"), Path("/bin"), Path("/sbin")]
        for p_root in prohibited_roots:
            try:
                if path_obj.is_relative_to(p_root):
                    raise ScanConfigurationError(f"Security Violation: Target path '{output_path}' points to protected system directory.")
            except (ValueError, AttributeError):
                pass

        if allowed_root_dir:
            allowed_resolved = allowed_root_dir.resolve()
            if not path_obj.is_relative_to(allowed_resolved):
                raise ScanConfigurationError(f"Security Violation: Output path '{path_obj}' is outside allowed root directory '{allowed_resolved}'.")

        return path_obj

    def export_to_file(
        self,
        report: UnifiedScanReport,
        format_type: ReportFormat,
        output_path: Union[str, Path],
        allowed_root_dir: Optional[Path] = None
    ) -> Path:
        """Generates report and writes to validated destination on disk."""
        resolved_path = self.validate_and_resolve_output_path(output_path, allowed_root_dir=allowed_root_dir)
        content = self.generate_report(report, format_type)

        # Create parent directories safely
        resolved_path.parent.mkdir(parents=True, exist_ok=True)
        resolved_path.write_text(content, encoding="utf-8")
        return resolved_path
