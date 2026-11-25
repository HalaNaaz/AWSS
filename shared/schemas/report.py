from datetime import datetime, timezone
from enum import Enum
from typing import List, Dict, Optional, Any
from uuid import UUID, uuid4
from pydantic import BaseModel, Field, ConfigDict

from shared.schemas.common import Severity, FindingStatus, ScanProfile, ScanStatus
from shared.schemas.finding import FindingResponse
from shared.schemas.discovery import TechnologyObservationSchema, AttackSurfaceSummarySchema


class ReportFormat(str, Enum):
    JSON = "json"
    HTML = "html"
    MARKDOWN = "markdown"
    SARIF = "sarif"


class SeveritySummarySchema(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    informational: int = 0
    total: int = 0

    @classmethod
    def from_findings(cls, findings: List[FindingResponse]) -> "SeveritySummarySchema":
        summary = cls()
        for f in findings:
            summary.total += 1
            if f.severity == Severity.CRITICAL:
                summary.critical += 1
            elif f.severity == Severity.HIGH:
                summary.high += 1
            elif f.severity == Severity.MEDIUM:
                summary.medium += 1
            elif f.severity == Severity.LOW:
                summary.low += 1
            elif f.severity == Severity.INFORMATIONAL:
                summary.informational += 1
        return summary


class UnifiedScanReport(BaseModel):
    """Authoritative structured unified scan report consolidating recon, passive, active, and attack surface findings."""
    scan_id: UUID
    target_url: str
    profile: ScanProfile
    status: ScanStatus
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: float = 0.0

    urls_crawled: int = 0
    endpoints_discovered: int = 0
    forms_discovered: int = 0

    technologies: List[TechnologyObservationSchema] = []
    severity_summary: SeveritySummarySchema = Field(default_factory=SeveritySummarySchema)
    findings: List[FindingResponse] = []
    attack_surface_summary: Optional[AttackSurfaceSummarySchema] = None

    model_config = ConfigDict(from_attributes=True)
