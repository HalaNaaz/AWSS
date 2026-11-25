from datetime import datetime
from typing import Optional, Dict, Any, List
from uuid import UUID
from pydantic import BaseModel, Field
from shared.schemas.common import Severity, FindingStatus
from shared.schemas.intelligence import FindingIntelligenceSchema


class EndpointSchema(BaseModel):
    url: str
    method: str = "GET"
    parameter: Optional[str] = None
    headers: Optional[Dict[str, str]] = None


class EvidenceSchema(BaseModel):
    request: str = Field(..., description="Redacted raw HTTP request trace")
    response: str = Field(..., description="Redacted raw HTTP response trace")
    sha256_hash: str = Field(..., description="Cryptographic SHA-256 integrity seal")
    probe_type: Optional[str] = Field(default="primary", description="Primary anomaly or secondary verification probe")
    created_at: Optional[datetime] = None


class FindingBase(BaseModel):
    title: str = Field(..., min_length=3, max_length=200)
    description: Optional[str] = None
    cwe_id: str = Field(..., description="CWE identifier, e.g. CWE-89")
    owasp_category: Optional[str] = Field(None, description="e.g. A03:2021 - Injection")
    severity: Severity = Severity.MEDIUM
    cvss_score: float = Field(..., ge=0.0, le=10.0)
    cvss_vector: Optional[str] = None
    status: FindingStatus = FindingStatus.SUSPECTED
    confidence: float = Field(default=0.7, ge=0.0, le=1.0)
    remediation: Optional[str] = None
    curl_reproduction: Optional[str] = None


class FindingCreate(FindingBase):
    scan_id: UUID
    endpoint: EndpointSchema
    evidence: Optional[EvidenceSchema] = None


class FindingResponse(FindingBase):
    id: UUID
    scan_id: UUID
    target_id: Optional[UUID] = None
    endpoint: EndpointSchema
    evidence: Optional[EvidenceSchema] = None
    intelligence: Optional[FindingIntelligenceSchema] = None
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True
