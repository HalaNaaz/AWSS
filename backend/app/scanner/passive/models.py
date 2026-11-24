from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from uuid import UUID, uuid4
from pydantic import BaseModel, Field

from shared.schemas.common import Severity, FindingStatus
from shared.schemas.discovery import FormMetadataSchema
from shared.schemas.finding import FindingCreate, FindingResponse, EndpointSchema, EvidenceSchema
from backend.app.scanner.evidence.redactor import EvidenceRedactor


class HTTPResponseContext(BaseModel):
    """Context representation of an observed HTTP request/response transaction for passive analysis."""
    url: str
    status_code: int = 200
    headers: Dict[str, str] = Field(default_factory=dict)
    raw_headers: List[tuple[str, str]] = Field(default_factory=list)
    body: Optional[str] = None
    method: str = "GET"
    request_headers: Optional[Dict[str, str]] = None
    request_body: Optional[str] = None
    forms: List[FormMetadataSchema] = Field(default_factory=list)

    def get_header(self, name: str, default: Optional[str] = None) -> Optional[str]:
        """Case-insensitive header lookup."""
        target = name.lower()
        for k, v in self.headers.items():
            if k.lower() == target:
                return v
        return default

    def get_all_header_values(self, name: str) -> List[str]:
        """Returns all values for a header name (case-insensitive) across raw headers and multi-values."""
        target = name.lower()
        values: List[str] = []
        if self.raw_headers:
            for k, v in self.raw_headers:
                if k.lower() == target:
                    values.append(v)
            if values:
                return values

        # Fallback to dictionary
        val = self.get_header(name)
        if val is not None:
            # Set-Cookie is often semicolon/comma separated in single strings if merged
            return [val]
        return []


class PassiveFinding(BaseModel):
    """Normalized security finding produced by a passive inspection module."""
    id: UUID = Field(default_factory=uuid4)
    rule_id: str
    title: str
    description: str
    cwe_id: str
    owasp_category: str
    severity: Severity = Severity.MEDIUM
    cvss_score: float = Field(ge=0.0, le=10.0)
    cvss_vector: Optional[str] = None
    status: FindingStatus = FindingStatus.DETECTED
    confidence: float = Field(default=0.85, ge=0.0, le=1.0)
    url: str
    parameter: Optional[str] = None
    evidence_request: str = ""
    evidence_response: str = ""
    evidence_hash: str = ""
    remediation: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def seal_evidence(self):
        """Redacts sensitive traces and computes SHA-256 seal."""
        redacted_req = EvidenceRedactor.redact(self.evidence_request or f"{self.url} [PASSIVE-ANALYSIS]")
        redacted_resp = EvidenceRedactor.redact(self.evidence_response)
        self.evidence_request = redacted_req
        self.evidence_response = redacted_resp
        self.evidence_hash = EvidenceRedactor.generate_sha256_seal(redacted_req, redacted_resp)

    def to_finding_response(self, scan_id: UUID) -> FindingResponse:
        """Converts into standard system FindingResponse contract."""
        if not self.evidence_hash:
            self.seal_evidence()

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
            curl_reproduction=f"curl -s -I '{self.url}'",
            endpoint=EndpointSchema(
                url=self.url,
                method="GET",
                parameter=self.parameter,
                headers={"evidence_rule": self.rule_id}
            ),
            evidence=EvidenceSchema(
                request=self.evidence_request,
                response=self.evidence_response,
                sha256_hash=self.evidence_hash,
                probe_type="passive_analysis",
                created_at=self.timestamp
            ),
            created_at=self.timestamp,
            updated_at=self.timestamp
        )
