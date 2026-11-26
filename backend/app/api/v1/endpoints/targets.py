from datetime import datetime, timezone
import ipaddress
from threading import RLock
from typing import Dict, List, Optional
from urllib.parse import urlparse
from uuid import UUID, uuid4

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field, field_validator

from backend.app.api.v1.endpoints.active import register_verified_target
from backend.app.core.config import settings
from backend.app.scanner.scope.scope_gate import ScopeGate
from shared.schemas.common import APIResponse, ScopeRuleType

router = APIRouter()

DEFAULT_CONTROLLED_TARGET_ID = UUID("00000000-0000-4000-8000-000000008089")


class TargetScopeRuleDTO(BaseModel):
    rule_type: ScopeRuleType = ScopeRuleType.INCLUDE
    pattern: str = Field(..., min_length=1, max_length=500)
    description: Optional[str] = None


class TargetCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    base_url: str = Field(..., min_length=8, max_length=2048)
    description: Optional[str] = Field(default=None, max_length=1000)
    asset_criticality: float = Field(default=3.0, ge=0.1, le=5.0)
    scope_rules: Optional[List[TargetScopeRuleDTO]] = None
    verified: bool = True

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        cleaned = value.strip()
        if len(cleaned) < 2:
            raise ValueError("Target name must contain at least 2 non-whitespace characters")
        return cleaned

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value: str) -> str:
        cleaned = value.strip().rstrip("/")
        parsed = urlparse(cleaned)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
            raise ValueError("Target URL must use http:// or https:// with a valid hostname")
        hostname = parsed.hostname
        if not hostname:
            raise ValueError("Target URL must specify a valid hostname or IP")
        if not settings.ALLOW_PRIVATE_IPS:
            try:
                ipaddress.ip_address(hostname)
            except ValueError:
                if hostname.lower() == "localhost":
                    raise ValueError("Target hostname 'localhost' violates ScopeGate anti-SSRF policy")
            else:
                gate = ScopeGate(cleaned, allow_private_ips=False)
                if gate.is_ip_prohibited(hostname):
                    raise ValueError(f"Target IP '{hostname}' violates ScopeGate anti-SSRF policy")
        return cleaned


class TargetRecordResponse(BaseModel):
    id: UUID
    name: str
    base_url: str
    description: Optional[str] = None
    asset_criticality: float = 3.0
    verified: bool = True
    scope_rules: List[TargetScopeRuleDTO] = Field(default_factory=list)
    created_at: datetime


class TargetRegistry:
    """Thread-safe in-memory authorized target & scope registry."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._targets: Dict[UUID, TargetRecordResponse] = {}
        self.seed_defaults()

    def seed_defaults(self) -> None:
        with self._lock:
            if DEFAULT_CONTROLLED_TARGET_ID not in self._targets:
                default_target = TargetRecordResponse(
                    id=DEFAULT_CONTROLLED_TARGET_ID,
                    name="Controlled Test Target",
                    base_url="http://127.0.0.1:8089",
                    description="Local controlled test application for authorized testing",
                    asset_criticality=3.0,
                    verified=True,
                    scope_rules=[
                        TargetScopeRuleDTO(
                            rule_type=ScopeRuleType.INCLUDE,
                            pattern="http://127.0.0.1:8089/*",
                            description="Authorized local test fixture boundary",
                        )
                    ],
                    created_at=datetime.now(timezone.utc),
                )
                self._targets[default_target.id] = default_target
                register_verified_target(
                    target_id=default_target.id,
                    base_url=default_target.base_url,
                    name=default_target.name,
                    verified=True,
                )

    def list_targets(self) -> List[TargetRecordResponse]:
        with self._lock:
            return list(self._targets.values())

    def get_target(self, target_id: UUID) -> Optional[TargetRecordResponse]:
        with self._lock:
            return self._targets.get(target_id)

    def create_target(self, req: TargetCreateRequest) -> TargetRecordResponse:
        with self._lock:
            target_id = uuid4()
            rules = req.scope_rules or [
                TargetScopeRuleDTO(
                    rule_type=ScopeRuleType.INCLUDE,
                    pattern=f"{req.base_url}/*",
                    description="Default base URL inclusion boundary",
                )
            ]
            record = TargetRecordResponse(
                id=target_id,
                name=req.name,
                base_url=req.base_url,
                description=req.description.strip() if req.description else None,
                asset_criticality=req.asset_criticality,
                verified=req.verified,
                scope_rules=rules,
                created_at=datetime.now(timezone.utc),
            )
            self._targets[target_id] = record
            register_verified_target(
                target_id=target_id,
                base_url=record.base_url,
                name=record.name,
                verified=record.verified,
            )
            return record

    def delete_target(self, target_id: UUID) -> bool:
        with self._lock:
            removed = self._targets.pop(target_id, None)
            return removed is not None

    def clear(self, reseed: bool = False) -> None:
        with self._lock:
            self._targets.clear()
        if reseed:
            self.seed_defaults()


target_registry = TargetRegistry()


@router.get("/", response_model=APIResponse[List[TargetRecordResponse]])
async def list_targets() -> APIResponse[List[TargetRecordResponse]]:
    """Lists all registered authorized targets and their ScopeGate boundary rules."""
    items = target_registry.list_targets()
    return APIResponse(
        success=True,
        message=f"Retrieved {len(items)} registered target(s).",
        data=items,
    )


@router.post("/", response_model=APIResponse[TargetRecordResponse], status_code=status.HTTP_201_CREATED)
async def create_target(target_in: TargetCreateRequest) -> APIResponse[TargetRecordResponse]:
    """Registers a new authorized application target with validated scope rules."""
    created = target_registry.create_target(target_in)
    return APIResponse(
        success=True,
        message=f"Registered authorized target '{created.name}'.",
        data=created,
    )


@router.get("/{target_id}", response_model=APIResponse[TargetRecordResponse])
async def get_target(target_id: UUID) -> APIResponse[TargetRecordResponse]:
    """Retrieves a specific target scope definition by ID."""
    target = target_registry.get_target(target_id)
    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target '{target_id}' not found.",
        )
    return APIResponse(
        success=True,
        message=f"Retrieved target '{target.name}'.",
        data=target,
    )


@router.delete("/{target_id}", response_model=APIResponse[Dict[str, str]])
async def delete_target(target_id: UUID) -> APIResponse[Dict[str, str]]:
    """Removes a target registration from the active registry."""
    if not target_registry.delete_target(target_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target '{target_id}' not found.",
        )
    return APIResponse(
        success=True,
        message=f"Deleted target '{target_id}'.",
        data={"id": str(target_id), "status": "DELETED"},
    )
