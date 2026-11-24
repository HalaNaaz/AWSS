from datetime import datetime
from typing import Optional, List
from uuid import UUID
from pydantic import BaseModel, HttpUrl, Field
from shared.schemas.common import ScopeRuleType


class ScopeRuleBase(BaseModel):
    rule_type: ScopeRuleType = ScopeRuleType.INCLUDE
    pattern: str = Field(..., description="Regex, wildcard, or CIDR scope pattern")
    description: Optional[str] = None


class ScopeRuleCreate(ScopeRuleBase):
    pass


class ScopeRuleResponse(ScopeRuleBase):
    id: UUID
    target_id: UUID
    created_at: datetime

    class Config:
        from_attributes = True


class TargetBase(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    base_url: str = Field(..., description="Target base URL, e.g. https://example.com")
    description: Optional[str] = None
    asset_criticality: float = Field(default=1.0, ge=0.1, le=2.0)


class TargetCreate(TargetBase):
    project_id: UUID
    scope_rules: Optional[List[ScopeRuleCreate]] = None


class TargetResponse(TargetBase):
    id: UUID
    project_id: UUID
    verified: bool = False
    created_at: datetime
    updated_at: Optional[datetime] = None
    scope_rules: List[ScopeRuleResponse] = []

    class Config:
        from_attributes = True
