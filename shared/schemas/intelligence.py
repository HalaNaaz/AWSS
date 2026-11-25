from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID
from pydantic import BaseModel, Field

from shared.schemas.common import Severity


class ConfidenceLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class CorrelationRelationship(str, Enum):
    DUPLICATE = "DUPLICATE"
    RELATED = "RELATED"
    POTENTIALLY_CORRELATED = "POTENTIALLY_CORRELATED"
    INDEPENDENT = "INDEPENDENT"


class ValidationState(str, Enum):
    DETECTED = "DETECTED"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    VALIDATION_PENDING = "VALIDATION_PENDING"
    VALIDATED = "VALIDATED"
    INCONCLUSIVE = "INCONCLUSIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    ACCEPTED_RISK = "ACCEPTED_RISK"
    RESOLVED = "RESOLVED"


class ContextualPriority(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class RemediationPriority(str, Enum):
    P0_IMMEDIATE = "P0_IMMEDIATE"
    P1_URGENT = "P1_URGENT"
    P2_SCHEDULED = "P2_SCHEDULED"
    P3_HARDENING = "P3_HARDENING"


class RemediationStatus(str, Enum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    FIXED = "FIXED"
    VERIFIED_FIXED = "VERIFIED_FIXED"
    WONT_FIX = "WONT_FIX"


class EvidenceReferenceSchema(BaseModel):
    evidence_id: str
    sha256_hash: str
    probe_type: str = "primary"
    source_module: str = "unknown"
    summary: Optional[str] = None
    timestamp: Optional[datetime] = None


class ConfidenceFactorSchema(BaseModel):
    factor: str
    score: float = Field(..., ge=0.0, le=1.0)
    weight: float = Field(..., ge=0.0, le=1.0)
    status: str = Field(..., description="POSITIVE | NEUTRAL | NEGATIVE | MISSING")
    detail: str


class ConfidenceAssessmentSchema(BaseModel):
    level: ConfidenceLevel
    score: float = Field(..., ge=0.0, le=1.0)
    factors: List[ConfidenceFactorSchema] = Field(default_factory=list)
    contributing_evidence: List[str] = Field(default_factory=list)
    missing_evidence: List[str] = Field(default_factory=list)
    contradictory_signals: List[str] = Field(default_factory=list)
    corroborated: bool = False
    needs_manual_review: bool = False
    explanation: str


class ValidationHistoryEntrySchema(BaseModel):
    from_state: Optional[ValidationState] = None
    to_state: ValidationState
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    actor: str = "system"
    validation_method: str = "initial_triage"
    supporting_evidence: Optional[str] = None
    evidence_sha256: Optional[str] = None
    notes: Optional[str] = None


class RiskFactorSchema(BaseModel):
    factor: str
    weight: float = Field(..., ge=0.0, le=1.0)
    raw_value: str
    contribution: float
    rationale: str


class ContextualRiskAssessmentSchema(BaseModel):
    contextual_priority: ContextualPriority
    contextual_score: float = Field(..., ge=0.0, le=100.0)
    severity_baseline: Severity
    cvss_baseline: float = Field(..., ge=0.0, le=10.0)
    confidence_level: ConfidenceLevel
    asset_criticality_used: Optional[float] = None
    risk_factors: List[RiskFactorSchema] = Field(default_factory=list)
    priority_rationale: str
    data_limitations: List[str] = Field(default_factory=list)


class RemediationIntelligenceSchema(BaseModel):
    root_cause: str
    why_it_matters: str
    affected_component: str
    recommended_remediation: str
    secure_implementation_guidance: str
    verification_guidance: str
    cwe_references: List[str] = Field(default_factory=list)
    owasp_references: List[str] = Field(default_factory=list)
    remediation_priority: RemediationPriority
    remediation_status: RemediationStatus = RemediationStatus.OPEN
    prerequisites: List[str] = Field(default_factory=list)


class CorrelationGroupSchema(BaseModel):
    group_id: str
    relationship_type: CorrelationRelationship
    primary_finding_id: UUID
    member_finding_ids: List[UUID] = Field(default_factory=list)
    correlation_confidence: float = Field(..., ge=0.0, le=1.0)
    explanation: str
    cwe_id: Optional[str] = None
    shared_attributes: List[str] = Field(default_factory=list)


class FindingIntelligenceSchema(BaseModel):
    fingerprint: str
    vulnerability_category: str
    target_id: Optional[UUID] = None
    normalized_endpoint: str
    http_method: str = "GET"
    parameter: Optional[str] = None
    asset_relationships: List[str] = Field(default_factory=list)
    technology_relationships: List[str] = Field(default_factory=list)
    detection_source: str = "unknown"
    detection_method: str = "unknown"
    evidence_references: List[EvidenceReferenceSchema] = Field(default_factory=list)

    correlation_group_id: Optional[str] = None
    correlation_relationship: CorrelationRelationship = CorrelationRelationship.INDEPENDENT
    correlation_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    correlation_explanation: Optional[str] = None
    is_primary: bool = True
    is_duplicate: bool = False
    duplicate_of: Optional[UUID] = None
    related_finding_ids: List[UUID] = Field(default_factory=list)

    confidence_assessment: ConfidenceAssessmentSchema
    validation_state: ValidationState = ValidationState.DETECTED
    validation_history: List[ValidationHistoryEntrySchema] = Field(default_factory=list)
    contextual_risk: ContextualRiskAssessmentSchema
    remediation_intelligence: RemediationIntelligenceSchema
    raw_module_metadata: Dict[str, Any] = Field(default_factory=dict)


class ScanIntelligenceSummarySchema(BaseModel):
    scan_id: UUID
    total_raw_findings: int = 0
    unique_primary_findings: int = 0
    duplicate_findings_count: int = 0
    correlation_groups_count: int = 0
    confidence_breakdown: Dict[str, int] = Field(default_factory=dict)
    validation_state_breakdown: Dict[str, int] = Field(default_factory=dict)
    contextual_priority_breakdown: Dict[str, int] = Field(default_factory=dict)
    manual_review_required_count: int = 0
    correlation_groups: List[CorrelationGroupSchema] = Field(default_factory=list)


class ValidationTransitionRequest(BaseModel):
    target_state: ValidationState
    actor: str = Field(default="analyst", min_length=1, max_length=100)
    validation_method: str = Field(default="analyst_review", min_length=1, max_length=100)
    notes: Optional[str] = Field(default=None, max_length=2000)
    supporting_evidence: Optional[str] = Field(default=None, max_length=4000)
    run_safe_revalidation: bool = False
    authorized: bool = False
    scan_id: Optional[UUID] = None
    target_id: Optional[UUID] = None


class RemediationStatusUpdateRequest(BaseModel):
    remediation_status: RemediationStatus
    actor: str = Field(default="analyst", min_length=1, max_length=100)
    notes: Optional[str] = Field(default=None, max_length=1000)


class RiskConfigUpdateRequest(BaseModel):
    asset_criticality: float = Field(..., ge=0.5, le=5.0)
    notes: Optional[str] = Field(default=None, max_length=1000)
