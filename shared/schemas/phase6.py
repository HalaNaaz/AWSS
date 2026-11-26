from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID
from pydantic import BaseModel, Field

from shared.schemas.common import ScanProfile, ScanStatus


class CoverageStatus(str, Enum):
    TESTED = "TESTED"
    PARTIAL = "PARTIAL"
    SKIPPED = "SKIPPED"
    UNTESTED = "UNTESTED"
    INCONCLUSIVE = "INCONCLUSIVE"


class PlannedTargetCheckSchema(BaseModel):
    url: str
    method: str = "GET"
    priority_score: float = Field(default=0.0, ge=0.0, le=100.0)
    selected_analyzers: List[str] = Field(default_factory=list)
    estimated_probes: int = Field(default=0, ge=0)
    rationale: str


class SkippedTargetCheckSchema(BaseModel):
    url: str
    analyzer_or_category: str
    reason: str


class ScanPlanSchema(BaseModel):
    scan_id: UUID
    target_url: str
    profile: ScanProfile
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    total_discovered_endpoints: int = 0
    planned_targets_count: int = 0
    skipped_targets_count: int = 0
    allocated_probe_budget: int = 0
    estimated_total_probes: int = 0
    rate_limit_rps: float = 10.0
    scope_enforced: bool = True
    technologies_context: List[str] = Field(default_factory=list)
    planned_checks: List[PlannedTargetCheckSchema] = Field(default_factory=list)
    skipped_checks: List[SkippedTargetCheckSchema] = Field(default_factory=list)
    planner_summary: str


class ContextAssessmentSuggestionSchema(BaseModel):
    suggestion_id: str
    target_url: str
    category: str
    priority: str = "MEDIUM"
    recommended_safe_check: str
    rationale: str
    context_signals: List[str] = Field(default_factory=list)
    related_existing_findings: int = 0


class ContextAssessmentReportSchema(BaseModel):
    scan_id: UUID
    evaluated_endpoints: int = 0
    evaluated_parameters: int = 0
    suggestions: List[ContextAssessmentSuggestionSchema] = Field(default_factory=list)
    summary: str


class OWASPCoverageEntrySchema(BaseModel):
    owasp_id: str
    owasp_name: str
    status: CoverageStatus
    checks_executed: List[str] = Field(default_factory=list)
    checks_skipped: List[str] = Field(default_factory=list)
    findings_detected: int = 0
    explanation: str


class SecurityCoverageReportSchema(BaseModel):
    scan_id: UUID
    profile: ScanProfile
    overall_dast_coverage_percent: float = Field(default=0.0, ge=0.0, le=100.0)
    tested_categories_count: int = 0
    partial_categories_count: int = 0
    skipped_categories_count: int = 0
    untested_categories_count: int = 0
    inconclusive_categories_count: int = 0
    owasp_categories: List[OWASPCoverageEntrySchema] = Field(default_factory=list)
    coverage_gaps: List[str] = Field(default_factory=list)
    honesty_disclaimer: str = (
        "DAST coverage reflects dynamic HTTP/HTML/API checks executed within authorized scope; "
        "categories requiring source code (SAST), dependency manifests (SCA), or infrastructure access remain untested or partial."
    )


class ExecutionReliabilityMetricsSchema(BaseModel):
    scan_id: UUID
    status: ScanStatus
    stage_timings_seconds: Dict[str, float] = Field(default_factory=dict)
    total_requests_attempted: int = 0
    successful_requests: int = 0
    retried_requests: int = 0
    timed_out_requests: int = 0
    rate_limited_429_count: int = 0
    scope_blocked_count: int = 0
    error_count: int = 0
    concurrency_limit: int = 5
    rate_limit_rps: float = 10.0
    was_cancelled: bool = False
    reliability_status: str = "HEALTHY"


class EvidenceIntelligenceSummarySchema(BaseModel):
    scan_id: UUID
    total_evidence_records: int = 0
    sealed_sha256_count: int = 0
    unsealed_count: int = 0
    redacted_secrets_confirmed: bool = True
    source_provenance_breakdown: Dict[str, int] = Field(default_factory=dict)
    reproducibility_breakdown: Dict[str, int] = Field(default_factory=dict)
    contradictory_evidence_count: int = 0
    missing_evidence_count: int = 0
    average_confidence_score: float = 0.0


class ScanTrendPointSchema(BaseModel):
    scan_id: UUID
    target_url: str
    created_at: datetime
    status: ScanStatus
    total_findings: int = 0
    unique_primary_findings: int = 0
    critical_high_count: int = 0
    coverage_percent: float = 0.0
    duration_seconds: float = 0.0


class ScanAnalyticsSchema(BaseModel):
    total_scans_analyzed: int = 0
    total_findings_across_scans: int = 0
    severity_distribution: Dict[str, int] = Field(default_factory=dict)
    validation_lifecycle_distribution: Dict[str, int] = Field(default_factory=dict)
    contextual_priority_distribution: Dict[str, int] = Field(default_factory=dict)
    top_vulnerable_categories: Dict[str, int] = Field(default_factory=dict)
    technology_risk_patterns: Dict[str, int] = Field(default_factory=dict)
    endpoint_exposure_breakdown: Dict[str, int] = Field(default_factory=dict)
    average_dast_coverage_percent: float = 0.0
    scan_trends: List[ScanTrendPointSchema] = Field(default_factory=list)


class ScanComparisonSchema(BaseModel):
    baseline_scan_id: UUID
    current_scan_id: UUID
    baseline_target_url: str
    current_target_url: str
    new_findings_count: int = 0
    resolved_findings_count: int = 0
    persisting_findings_count: int = 0
    new_finding_fingerprints: List[str] = Field(default_factory=list)
    resolved_finding_fingerprints: List[str] = Field(default_factory=list)
    persisting_finding_fingerprints: List[str] = Field(default_factory=list)
    coverage_delta_percent: float = 0.0
    summary: str
