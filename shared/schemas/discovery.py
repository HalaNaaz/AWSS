from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any
from uuid import UUID
from pydantic import BaseModel, Field, ConfigDict


class EndpointCategory(str, Enum):
    PAGE = "PAGE"
    API = "API"
    JAVASCRIPT = "JAVASCRIPT"
    CSS = "CSS"
    IMAGE = "IMAGE"
    DOCUMENT = "DOCUMENT"
    FORM = "FORM"
    REDIRECT = "REDIRECT"
    WEBSOCKET = "WEBSOCKET"
    OTHER = "OTHER"


class DiscoveryMethod(str, Enum):
    CRAWLER = "CRAWLER"
    ROBOTS_TXT = "ROBOTS_TXT"
    SITEMAP_XML = "SITEMAP_XML"
    JAVASCRIPT_AST = "JAVASCRIPT_AST"
    FORM_ACTION = "FORM_ACTION"
    HEADER_METADATA = "HEADER_METADATA"
    STATIC_JS_ANALYSIS = "STATIC_JS_ANALYSIS"
    API_SPEC = "API_SPEC"
    HTML_REDIRECT = "HTML_REDIRECT"


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
    is_confirmed: bool = False
    indicators_count: int = 1
    created_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


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
    confidence: float = Field(default=0.9, ge=0.0, le=1.0)


class DiscoveredEndpointResponse(DiscoveredEndpointCreate):
    id: UUID
    created_at: datetime
    updated_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


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


# ==========================================
# Phase 4: Attack Surface Discovery Schemas
# ==========================================

class ParameterCategory(str, Enum):
    AUTH = "AUTH"
    SESSION = "SESSION"
    REDIRECT = "REDIRECT"
    FILE = "FILE"
    SEARCH = "SEARCH"
    PAGINATION = "PAGINATION"
    IDENTIFIER = "IDENTIFIER"
    URL = "URL"
    SENSITIVE = "SENSITIVE"
    UNKNOWN = "UNKNOWN"


class ParameterLocation(str, Enum):
    QUERY = "QUERY"
    BODY = "BODY"
    PATH = "PATH"
    HEADER = "HEADER"
    COOKIE = "COOKIE"


class ParameterIntelligenceSchema(BaseModel):
    name: str
    location: ParameterLocation = ParameterLocation.QUERY
    category: ParameterCategory = ParameterCategory.UNKNOWN
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    endpoints_found: List[str] = []
    sample_values_redacted: List[str] = []
    risk_signals: List[str] = []


class APIType(str, Enum):
    REST = "REST"
    GRAPHQL = "GRAPHQL"
    OPENAPI = "OPENAPI"
    JSON_API = "JSON_API"
    WEBSOCKET = "WEBSOCKET"
    RPC = "RPC"
    OTHER = "OTHER"


class APIEndpointSchema(BaseModel):
    url: str
    method: str = "GET"
    api_type: APIType = APIType.REST
    version: Optional[str] = None
    auth_required: bool = False
    parameters: List[str] = []
    discovery_source: str = "CRAWLER"
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)


class AssetType(str, Enum):
    JAVASCRIPT = "JAVASCRIPT"
    CSS = "CSS"
    IMAGE = "IMAGE"
    FONT = "FONT"
    DOCUMENT = "DOCUMENT"
    SOURCEMAP = "SOURCEMAP"
    OTHER = "OTHER"


class AssetIntelligenceSchema(BaseModel):
    url: str
    asset_type: AssetType = AssetType.OTHER
    mime_type: Optional[str] = None
    size_bytes: Optional[int] = None
    discovery_source: str = "CRAWLER"
    in_scope: bool = True
    associated_endpoints: List[str] = []


class NodeType(str, Enum):
    DOMAIN = "DOMAIN"
    URL = "URL"
    ENDPOINT = "ENDPOINT"
    PARAMETER = "PARAMETER"
    FORM = "FORM"
    JS_ASSET = "JS_ASSET"
    API_ROUTE = "API_ROUTE"
    TECHNOLOGY = "TECHNOLOGY"
    FINDING = "FINDING"
    SOURCE = "SOURCE"


class EdgeType(str, Enum):
    LINKS_TO = "LINKS_TO"
    DISCOVERED_FROM = "DISCOVERED_FROM"
    HAS_PARAMETER = "HAS_PARAMETER"
    USES_ASSET = "USES_ASSET"
    ASSOCIATED_WITH = "ASSOCIATED_WITH"
    HOSTED_ON = "HOSTED_ON"
    HAS_FINDING = "HAS_FINDING"
    REFERENCES = "REFERENCES"


class AttackSurfaceNode(BaseModel):
    id: str
    label: str
    node_type: NodeType
    metadata: Dict[str, Any] = {}


class AttackSurfaceEdge(BaseModel):
    id: str
    source: str
    target: str
    edge_type: EdgeType
    metadata: Dict[str, Any] = {}


class AttackSurfaceGraphSchema(BaseModel):
    scan_id: UUID
    nodes: List[AttackSurfaceNode] = []
    edges: List[AttackSurfaceEdge] = []
    node_count: int = 0
    edge_count: int = 0


class PriorityLevel(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class PrioritizedEndpointSchema(BaseModel):
    url: str
    method: str = "GET"
    priority_score: float = Field(default=0.0, ge=0.0, le=100.0)
    priority_level: PriorityLevel = PriorityLevel.LOW
    risk_signals: List[str] = []
    auth_required: bool = False
    has_parameters: bool = False
    findings_count: int = 0


class AttackSurfaceSummarySchema(BaseModel):
    scan_id: UUID
    target_url: str
    total_endpoints: int = 0
    total_parameters: int = 0
    total_apis: int = 0
    total_assets: int = 0
    total_technologies: int = 0
    graph_nodes_count: int = 0
    graph_edges_count: int = 0
    high_priority_endpoints_count: int = 0
    parameter_categories_breakdown: Dict[str, int] = {}
    api_types_breakdown: Dict[str, int] = {}
    asset_types_breakdown: Dict[str, int] = {}
