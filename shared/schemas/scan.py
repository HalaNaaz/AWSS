from datetime import datetime
from typing import Optional, Dict, Any
from uuid import UUID
from pydantic import BaseModel, Field
from shared.schemas.common import ScanProfile, ScanStatus


# Profile resource limit presets
SCAN_PROFILE_PRESETS: Dict[ScanProfile, Dict[str, Any]] = {
    ScanProfile.PASSIVE_DISCOVERY: {
        "max_crawl_depth": 2,
        "max_urls": 100,
        "concurrency": 3,
        "rate_limit_rps": 5.0,
        "request_budget": 0,
        "active_enabled": False,
    },
    ScanProfile.PASSIVE_ONLY: {
        "max_crawl_depth": 2,
        "max_urls": 100,
        "concurrency": 3,
        "rate_limit_rps": 5.0,
        "request_budget": 0,
        "active_enabled": False,
    },
    ScanProfile.SAFE_ACTIVE: {
        "max_crawl_depth": 2,
        "max_urls": 50,
        "concurrency": 2,
        "rate_limit_rps": 3.0,
        "request_budget": 60,
        "active_enabled": True,
    },
    ScanProfile.STANDARD_ACTIVE: {
        "max_crawl_depth": 3,
        "max_urls": 200,
        "concurrency": 4,
        "rate_limit_rps": 8.0,
        "request_budget": 250,
        "active_enabled": True,
    },
    ScanProfile.QUICK_ASSESSMENT: {
        "max_crawl_depth": 3,
        "max_urls": 300,
        "concurrency": 5,
        "rate_limit_rps": 10.0,
        "request_budget": 0,
        "active_enabled": False,
    },
    ScanProfile.FULL_ASSESSMENT: {
        "max_crawl_depth": 5,
        "max_urls": 1000,
        "concurrency": 8,
        "rate_limit_rps": 15.0,
        "request_budget": 500,
        "active_enabled": True,
    },
    ScanProfile.SAFE_MODE: {
        "max_crawl_depth": 2,
        "max_urls": 50,
        "concurrency": 1,
        "rate_limit_rps": 2.0,
        "request_budget": 0,
        "active_enabled": False,
    },
    ScanProfile.API_TARGETED: {
        "max_crawl_depth": 3,
        "max_urls": 500,
        "concurrency": 5,
        "rate_limit_rps": 10.0,
        "request_budget": 100,
        "active_enabled": True,
    },
}


class ScanJobBase(BaseModel):
    profile: ScanProfile = ScanProfile.QUICK_ASSESSMENT
    max_crawl_depth: int = Field(default=3, ge=1, le=10)
    max_urls: int = Field(default=500, ge=1, le=10000)
    concurrency: int = Field(default=5, ge=1, le=30)
    rate_limit_rps: float = Field(default=10.0, ge=0.5, le=50.0)


class ScanJobCreate(ScanJobBase):
    target_id: Optional[UUID] = None
    target_url: Optional[str] = None
    asset_criticality: Optional[float] = Field(default=None, ge=0.5, le=5.0)
    parameters: Optional[Dict[str, Any]] = None


class ScanJobResponse(ScanJobBase):
    id: UUID
    target_id: Optional[UUID] = None
    target_url: Optional[str] = None
    asset_criticality: Optional[float] = None
    status: ScanStatus = ScanStatus.QUEUED
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    urls_crawled: int = 0
    findings_count: int = 0
    error_message: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True
