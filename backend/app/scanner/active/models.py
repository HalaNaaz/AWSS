from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from uuid import UUID, uuid4
from pydantic import BaseModel, Field

from shared.schemas.common import Severity, FindingStatus
from shared.schemas.finding import FindingResponse, EndpointSchema, EvidenceSchema
from backend.app.scanner.evidence.redactor import EvidenceRedactor


class ActiveTarget(BaseModel):
    """Represents an application attack surface target endpoint for active security inspection."""
    url: str
    method: str = "GET"
    parameters: Dict[str, str] = Field(default_factory=dict)
    body_params: Dict[str, str] = Field(default_factory=dict)
    headers: Dict[str, str] = Field(default_factory=dict)
    baseline_status: Optional[int] = None
    baseline_body: Optional[str] = None
    baseline_headers: Dict[str, str] = Field(default_factory=dict)
    content_type: Optional[str] = None


class ActiveFinding(BaseModel):
    """Normalized security finding produced by an active inspection module."""
    id: UUID = Field(default_factory=uuid4)
    rule_id: str
    title: str
    description: str
    cwe_id: str
    owasp_category: str
    severity: Severity = Severity.MEDIUM
    cvss_score: float = Field(ge=0.0, le=10.0)
    cvss_vector: Optional[str] = None
    status: FindingStatus = FindingStatus.SUSPECTED
    confidence: float = Field(default=0.85, ge=0.0, le=1.0)
    url: str
    parameter: Optional[str] = None
    http_method: str = "GET"
    evidence_request: str = ""
    evidence_response: str = ""
    evidence_hash: str = ""
    remediation: str
    detection_module: str
    probe_count: int = 1
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def to_finding_response(self, scan_id: UUID) -> FindingResponse:
        """Converts an ActiveFinding into the authoritative FindingResponse schema."""
        redacted_req = EvidenceRedactor.redact(self.evidence_request)
        redacted_resp = EvidenceRedactor.redact(self.evidence_response)
        evidence_hash = self.evidence_hash or EvidenceRedactor.generate_sha256_seal(redacted_req, redacted_resp)

        evidence_schema = None
        if self.evidence_request or self.evidence_response:
            evidence_schema = EvidenceSchema(
                request=redacted_req,
                response=redacted_resp,
                sha256_hash=evidence_hash,
                probe_type="active_probe",
                created_at=self.timestamp,
            )

        return FindingResponse(
            id=self.id,
            scan_id=scan_id,
            title=self.title,
            description=self.description,
            cwe_id=self.cwe_id,
            owasp_category=self.owasp_category,
            severity=self.severity,
            cvss_score=self.cvss_score,
            cvss_vector=self.cvss_vector,
            status=self.status,
            confidence=self.confidence,
            remediation=self.remediation,
            endpoint=EndpointSchema(
                url=self.url,
                method=self.http_method,
                parameter=self.parameter,
            ),
            evidence=evidence_schema,
            created_at=self.timestamp,
        )


class RequestBudgetTracker:
    """Thread-safe request budget and rate tracker for active scanning."""

    def __init__(self, budget: int = 100):
        self._initial_budget = budget
        self._remaining_budget = budget
        self._requests_sent = 0

    @property
    def remaining(self) -> int:
        return self._remaining_budget

    @property
    def total_sent(self) -> int:
        return self._requests_sent

    def can_request(self) -> bool:
        return self._remaining_budget > 0

    def consume(self, count: int = 1) -> bool:
        if self._remaining_budget >= count:
            self._remaining_budget -= count
            self._requests_sent += count
            return True
        return False
