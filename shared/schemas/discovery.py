from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any
from uuid import UUID
from pydantic import BaseModel, Field


class EndpointCategory(str, Enum):
    PAGE = "PAGE"
    API = "API"
    JAVASCRIPT = "JAVASCRIPT"
    CSS = "CSS"
    IMAGE = "IMAGE"
    DOCUMENT = "DOCUMENT"
    FORM = "FORM"
    REDIRECT = "REDIRECT"
    OTHER = "OTHER"


class DiscoveryMethod(str, Enum):
    CRAWLER = "CRAWLER"
    ROBOTS_TXT = "ROBOTS_TXT"
    SITEMAP_XML = "SITEMAP_XML"
    JAVASCRIPT_AST = "JAVASCRIPT_AST"
    FORM_ACTION = "FORM_ACTION"
    HEADER_METADATA = "HEADER_METADATA"


class FormFieldSchema(BaseModel):
    name: str
    field_type: str = "text"
    default_value: Optional[str] = None
    is_required: bool = False


class FormMetadataSchema(BaseModel):
    action: str
    method: str = "POST"
    fields: List[FormFieldSchema] = []
    enctype: Optional[str] = None
    source_url: Optional[str] = None


class TechnologyObservationSchema(BaseModel):
    id: Optional[UUID] = None
    scan_id: UUID
    technology_name: str
    category: str
    version: Optional[str] = None
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    detection_source: str
    evidence: Optional[str] = None
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class DiscoveredEndpointCreate(BaseModel):
    scan_id: UUID
    url: str
    normalized_url: str
    method: str = "GET"
    parameter: Optional[str] = None
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    response_size: Optional[int] = None
    response_time_ms: Optional[float] = None
    source_url: Optional[str] = None
    discovery_method: DiscoveryMethod = DiscoveryMethod.CRAWLER
    crawl_depth: int = 0
    endpoint_category: EndpointCategory = EndpointCategory.PAGE
    query_params: Optional[Dict[str, Any]] = None


class DiscoveredEndpointResponse(DiscoveredEndpointCreate):
    id: UUID
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class ReconStartRequest(BaseModel):
    target_id: UUID
    max_crawl_depth: int = Field(default=3, ge=1, le=10)
    max_urls: int = Field(default=500, ge=1, le=10000)
    concurrency: int = Field(default=5, ge=1, le=30)
    rate_limit_rps: float = Field(default=10.0, ge=0.5, le=50.0)
    analyze_javascript: bool = True
    respect_robots: bool = True


class ReconSummaryResponse(BaseModel):
    scan_id: UUID
    target_url: str
    status: str
    urls_crawled: int
    endpoints_discovered: int
    forms_discovered: int
    technologies_detected: int
    crawl_depth_reached: int
    execution_time_seconds: float
    categories_breakdown: Dict[str, int] = {}
    technologies: List[TechnologyObservationSchema] = []
    findings_count: int = 0
    findings: List[Any] = []
