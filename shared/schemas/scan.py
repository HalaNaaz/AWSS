from datetime import datetime
from typing import Optional, Dict, Any
from uuid import UUID
from pydantic import BaseModel, Field
from shared.schemas.common import ScanProfile, ScanStatus


class ScanJobBase(BaseModel):
    profile: ScanProfile = ScanProfile.QUICK_ASSESSMENT
    max_crawl_depth: int = Field(default=3, ge=1, le=10)
    max_urls: int = Field(default=500, ge=1, le=10000)
    concurrency: int = Field(default=5, ge=1, le=30)
    rate_limit_rps: float = Field(default=10.0, ge=0.5, le=50.0)


class ScanJobCreate(ScanJobBase):
    target_id: UUID
    parameters: Optional[Dict[str, Any]] = None


class ScanJobResponse(ScanJobBase):
    id: UUID
    target_id: UUID
    status: ScanStatus = ScanStatus.QUEUED
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    urls_crawled: int = 0
    findings_count: int = 0
    error_message: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True
