from enum import Enum
from typing import Generic, Optional, TypeVar, List
from pydantic import BaseModel, Field

T = TypeVar("T")


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class FindingStatus(str, Enum):
    DETECTED = "DETECTED"
    CANDIDATE = "CANDIDATE"
    SUSPECTED = "SUSPECTED"
    VERIFICATION_PENDING = "VERIFICATION_PENDING"
    VERIFIED = "VERIFIED"
    UNVERIFIED = "UNVERIFIED"
    NOT_VULNERABLE = "NOT_VULNERABLE"
    INCONCLUSIVE = "INCONCLUSIVE"
    NOT_TESTED = "NOT_TESTED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    RESOLVED = "RESOLVED"
    ACCEPTED_RISK = "ACCEPTED_RISK"
    ERROR = "ERROR"


class ScanProfile(str, Enum):
    PASSIVE_DISCOVERY = "PASSIVE_DISCOVERY"
    QUICK_ASSESSMENT = "QUICK_ASSESSMENT"
    FULL_ASSESSMENT = "FULL_ASSESSMENT"
    AUTHENTICATED_SCAN = "AUTHENTICATED_SCAN"
    API_TARGETED = "API_TARGETED"
    SAFE_MODE = "SAFE_MODE"


class ScanStatus(str, Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    PRE_FLIGHT = "PRE_FLIGHT"
    CRAWLING = "CRAWLING"
    ACTIVE_SCAN = "ACTIVE_SCAN"
    VERIFYING = "VERIFYING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    PAUSED = "PAUSED"
    CANCELLED = "CANCELLED"


class ScopeRuleType(str, Enum):
    INCLUDE = "INCLUDE"
    EXCLUDE = "EXCLUDE"


class APIResponse(BaseModel, Generic[T]):
    success: bool = True
    message: Optional[str] = None
    data: Optional[T] = None
    errors: Optional[List[str]] = None


class PaginatedResponse(BaseModel, Generic[T]):
    items: List[T]
    total: int
    page: int
    page_size: int
    total_pages: int
