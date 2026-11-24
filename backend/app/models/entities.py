import uuid
from typing import Optional, List
from sqlalchemy import (
    String, Text, Boolean, Float, Integer, ForeignKey, Enum as SQLEnum, Index
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from shared.schemas.common import Severity, FindingStatus, ScanProfile, ScanStatus, ScopeRuleType


class Organization(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "organizations"

    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)

    users: Mapped[List["User"]] = relationship("User", back_populates="organization", cascade="all, delete-orphan")
    projects: Mapped[List["Project"]] = relationship("Project", back_populates="organization", cascade="all, delete-orphan")
    audit_logs: Mapped[List["AuditLog"]] = relationship("AuditLog", back_populates="organization")


class User(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "users"

    org_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    role: Mapped[str] = mapped_column(String(50), default="Analyst", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    organization: Mapped["Organization"] = relationship("Organization", back_populates="users")


class Project(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "projects"

    org_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    organization: Mapped["Organization"] = relationship("Organization", back_populates="projects")
    targets: Mapped[List["Target"]] = relationship("Target", back_populates="project", cascade="all, delete-orphan")


class Target(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "targets"

    project_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    base_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    asset_criticality: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)
    verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    project: Mapped["Project"] = relationship("Project", back_populates="targets")
    scope_rules: Mapped[List["ScopeRule"]] = relationship("ScopeRule", back_populates="target", cascade="all, delete-orphan")
    scan_jobs: Mapped[List["ScanJob"]] = relationship("ScanJob", back_populates="target", cascade="all, delete-orphan")


class ScopeRule(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "scope_rules"

    target_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False)
    rule_type: Mapped[ScopeRuleType] = mapped_column(SQLEnum(ScopeRuleType), default=ScopeRuleType.INCLUDE, nullable=False)
    pattern: Mapped[str] = mapped_column(String(1024), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    target: Mapped["Target"] = relationship("Target", back_populates="scope_rules")


class ScanJob(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "scan_jobs"

    target_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False)
    profile: Mapped[ScanProfile] = mapped_column(SQLEnum(ScanProfile), default=ScanProfile.QUICK_ASSESSMENT, nullable=False)
    status: Mapped[ScanStatus] = mapped_column(SQLEnum(ScanStatus), default=ScanStatus.QUEUED, nullable=False, index=True)
    max_crawl_depth: Mapped[int] = mapped_column(Integer, default=3, nullable=False)
    max_urls: Mapped[int] = mapped_column(Integer, default=500, nullable=False)
    concurrency: Mapped[int] = mapped_column(Integer, default=5, nullable=False)
    rate_limit_rps: Mapped[float] = mapped_column(Float, default=10.0, nullable=False)
    urls_crawled: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    findings_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    target: Mapped["Target"] = relationship("Target", back_populates="scan_jobs")
    endpoints: Mapped[List["DiscoveredEndpoint"]] = relationship("DiscoveredEndpoint", back_populates="scan_job", cascade="all, delete-orphan")
    findings: Mapped[List["Finding"]] = relationship("Finding", back_populates="scan_job", cascade="all, delete-orphan")


class DiscoveredEndpoint(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "discovered_endpoints"

    scan_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False)
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    method: Mapped[str] = mapped_column(String(10), default="GET", nullable=False)
    parameter: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    status_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    content_type: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    scan_job: Mapped["ScanJob"] = relationship("ScanJob", back_populates="endpoints")
    findings: Mapped[List["Finding"]] = relationship("Finding", back_populates="endpoint")

    __table_args__ = (
        Index("idx_endpoints_scan_url", "scan_id", "url"),
    )


class Finding(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "findings"

    scan_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False)
    endpoint_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("discovered_endpoints.id", ondelete="SET NULL"), nullable=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    cwe_id: Mapped[str] = mapped_column(String(50), nullable=False)
    owasp_category: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    severity: Mapped[Severity] = mapped_column(SQLEnum(Severity), default=Severity.MEDIUM, nullable=False, index=True)
    cvss_score: Mapped[float] = mapped_column(Float, nullable=False)
    cvss_vector: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    status: Mapped[FindingStatus] = mapped_column(SQLEnum(FindingStatus), default=FindingStatus.SUSPECTED, nullable=False, index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.7, nullable=False)
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    curl_reproduction: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    scan_job: Mapped["ScanJob"] = relationship("ScanJob", back_populates="findings")
    endpoint: Mapped[Optional["DiscoveredEndpoint"]] = relationship("DiscoveredEndpoint", back_populates="findings")
    evidence: Mapped[List["EvidenceRecord"]] = relationship("EvidenceRecord", back_populates="finding", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_findings_scan_severity", "scan_id", "severity", "status"),
    )


class EvidenceRecord(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "evidence_records"

    finding_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False)
    request_data: Mapped[str] = mapped_column(Text, nullable=False)
    response_data: Mapped[str] = mapped_column(Text, nullable=False)
    sha256_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    probe_type: Mapped[str] = mapped_column(String(50), default="primary", nullable=False)

    finding: Mapped["Finding"] = relationship("Finding", back_populates="evidence")


class AuditLog(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "audit_logs"

    org_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), nullable=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    target_resource: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    details: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    organization: Mapped["Organization"] = relationship("Organization", back_populates="audit_logs")
