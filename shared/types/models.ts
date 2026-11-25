/**
 * Ashlynx WebSec Scanner - Unified TypeScript Interfaces
 * Corresponds to shared/schemas Python models
 */

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL";

export type FindingStatus =
  | "DETECTED"
  | "CANDIDATE"
  | "SUSPECTED"
  | "VERIFICATION_PENDING"
  | "VERIFIED"
  | "UNVERIFIED"
  | "NOT_VULNERABLE"
  | "INCONCLUSIVE"
  | "NOT_TESTED"
  | "FALSE_POSITIVE"
  | "RESOLVED"
  | "ACCEPTED_RISK"
  | "ERROR";

export type ScanProfile =
  | "PASSIVE_DISCOVERY"
  | "PASSIVE_ONLY"
  | "SAFE_ACTIVE"
  | "STANDARD_ACTIVE"
  | "QUICK_ASSESSMENT"
  | "FULL_ASSESSMENT"
  | "AUTHENTICATED_SCAN"
  | "API_TARGETED"
  | "SAFE_MODE";

export type ScanStatus =
  | "QUEUED"
  | "RUNNING"
  | "PRE_FLIGHT"
  | "CRAWLING"
  | "ACTIVE_SCAN"
  | "VERIFYING"
  | "COMPLETED"
  | "FAILED"
  | "PAUSED"
  | "CANCELLED";

export type ScopeRuleType = "INCLUDE" | "EXCLUDE";

export type EndpointCategory =
  | "PAGE"
  | "API"
  | "JAVASCRIPT"
  | "CSS"
  | "IMAGE"
  | "DOCUMENT"
  | "FORM"
  | "REDIRECT"
  | "WEBSOCKET"
  | "OTHER";

export type DiscoveryMethod =
  | "CRAWLER"
  | "ROBOTS_TXT"
  | "SITEMAP_XML"
  | "JAVASCRIPT_AST"
  | "FORM_ACTION"
  | "HEADER_METADATA"
  | "STATIC_JS_ANALYSIS"
  | "API_SPEC"
  | "HTML_REDIRECT";

export interface ScopeRule {
  id: string;
  target_id: string;
  rule_type: ScopeRuleType;
  pattern: string;
  description?: string;
  created_at: string;
}

export interface Target {
  id: string;
  project_id: string;
  name: string;
  base_url: string;
  description?: string;
  asset_criticality: number;
  verified: boolean;
  created_at: string;
  updated_at?: string;
  scope_rules?: ScopeRule[];
}

export interface ScanJob {
  id: string;
  target_id: string;
  profile: ScanProfile;
  status: ScanStatus;
  max_crawl_depth: number;
  max_urls: number;
  concurrency: number;
  rate_limit_rps: number;
  started_at?: string;
  completed_at?: string;
  urls_crawled: number;
  findings_count: number;
  error_message?: string;
  created_at: string;
}

export interface Endpoint {
  url: string;
  method: string;
  parameter?: string;
  headers?: Record<string, string>;
}

export interface Evidence {
  request: string;
  response: string;
  sha256_hash: string;
  probe_type?: string;
  created_at?: string;
}

export interface Finding {
  id: string;
  scan_id: string;
  title: string;
  description?: string;
  cwe_id: string;
  owasp_category?: string;
  severity: Severity;
  cvss_score: number;
  cvss_vector?: string;
  status: FindingStatus;
  confidence: number;
  remediation?: string;
  curl_reproduction?: string;
  endpoint: Endpoint;
  evidence?: Evidence;
  created_at: string;
  updated_at?: string;
}

export interface FormField {
  name: string;
  field_type: string;
  default_value?: string;
  is_required: boolean;
}

export interface FormMetadata {
  action: string;
  method: string;
  fields: FormField[];
  enctype?: string;
  source_url?: string;
}

export interface TechnologyObservation {
  id?: string;
  scan_id: string;
  technology_name: string;
  category: string;
  version?: string;
  confidence: number;
  detection_source: string;
  evidence?: string;
  is_confirmed?: boolean;
  indicators_count?: number;
  created_at?: string;
}

export interface DiscoveredEndpoint {
  id: string;
  scan_id: string;
  url: string;
  normalized_url: string;
  method: string;
  parameter?: string;
  status_code?: number;
  content_type?: string;
  response_size?: number;
  response_time_ms?: number;
  source_url?: string;
  discovery_method: DiscoveryMethod;
  crawl_depth: number;
  endpoint_category: EndpointCategory;
  query_params?: Record<string, any>;
  confidence?: number;
  created_at: string;
}

export interface ReconSummary {
  scan_id: string;
  target_url: string;
  status: string;
  urls_crawled: number;
  endpoints_discovered: number;
  forms_discovered: number;
  technologies_detected: number;
  crawl_depth_reached: number;
  execution_time_seconds: number;
  categories_breakdown: Record<string, number>;
  technologies: TechnologyObservation[];
  findings_count?: number;
  findings?: Finding[];
}

export type ReportFormat = "json" | "html" | "markdown" | "sarif";

export interface SeveritySummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
  total: number;
}

export interface UnifiedScanReport {
  scan_id: string;
  target_url: string;
  profile: ScanProfile;
  status: ScanStatus;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  duration_seconds: number;
  urls_crawled: number;
  endpoints_discovered: number;
  forms_discovered: number;
  technologies: TechnologyObservation[];
  severity_summary: SeveritySummary;
  findings: Finding[];
  attack_surface_summary?: AttackSurfaceSummary;
}

export interface APIResponse<T> {
  success: boolean;
  message?: string;
  data?: T;
  errors?: string[];
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

// ==========================================
// Phase 4: Attack Surface Discovery Interfaces
// ==========================================

export type ParameterCategory =
  | "AUTH"
  | "SESSION"
  | "REDIRECT"
  | "FILE"
  | "SEARCH"
  | "PAGINATION"
  | "IDENTIFIER"
  | "URL"
  | "SENSITIVE"
  | "UNKNOWN";

export type ParameterLocation = "QUERY" | "BODY" | "PATH" | "HEADER" | "COOKIE";

export interface ParameterIntelligence {
  name: string;
  location: ParameterLocation;
  category: ParameterCategory;
  confidence: number;
  endpoints_found: string[];
  sample_values_redacted: string[];
  risk_signals: string[];
}

export type APIType =
  | "REST"
  | "GRAPHQL"
  | "OPENAPI"
  | "JSON_API"
  | "WEBSOCKET"
  | "RPC"
  | "OTHER";

export interface APIEndpoint {
  url: string;
  method: string;
  api_type: APIType;
  version?: string;
  auth_required: boolean;
  parameters: string[];
  discovery_source: string;
  confidence: number;
}

export type AssetType =
  | "JAVASCRIPT"
  | "CSS"
  | "IMAGE"
  | "FONT"
  | "DOCUMENT"
  | "SOURCEMAP"
  | "OTHER";

export interface AssetIntelligence {
  url: string;
  asset_type: AssetType;
  mime_type?: string;
  size_bytes?: number;
  discovery_source: string;
  in_scope: boolean;
  associated_endpoints: string[];
}

export type NodeType =
  | "DOMAIN"
  | "URL"
  | "ENDPOINT"
  | "PARAMETER"
  | "FORM"
  | "JS_ASSET"
  | "API_ROUTE"
  | "TECHNOLOGY"
  | "FINDING"
  | "SOURCE";

export type EdgeType =
  | "LINKS_TO"
  | "DISCOVERED_FROM"
  | "HAS_PARAMETER"
  | "USES_ASSET"
  | "ASSOCIATED_WITH"
  | "HOSTED_ON"
  | "HAS_FINDING"
  | "REFERENCES";

export interface AttackSurfaceNode {
  id: string;
  label: string;
  node_type: NodeType;
  metadata?: Record<string, any>;
}

export interface AttackSurfaceEdge {
  id: string;
  source: string;
  target: string;
  edge_type: EdgeType;
  metadata?: Record<string, any>;
}

export interface AttackSurfaceGraph {
  scan_id: string;
  nodes: AttackSurfaceNode[];
  edges: AttackSurfaceEdge[];
  node_count: number;
  edge_count: number;
}

export type PriorityLevel = "HIGH" | "MEDIUM" | "LOW";

export interface PrioritizedEndpoint {
  url: string;
  method: string;
  priority_score: number;
  priority_level: PriorityLevel;
  risk_signals: string[];
  auth_required: boolean;
  has_parameters: boolean;
  findings_count: number;
}

export interface AttackSurfaceSummary {
  scan_id: string;
  target_url: string;
  total_endpoints: number;
  total_parameters: number;
  total_apis: number;
  total_assets: number;
  total_technologies: number;
  graph_nodes_count: number;
  graph_edges_count: number;
  high_priority_endpoints_count: number;
  parameter_categories_breakdown: Record<string, number>;
  api_types_breakdown: Record<string, number>;
  asset_types_breakdown: Record<string, number>;
}
