/**
 * Ashlynx WebSec Scanner - Unified TypeScript Interfaces
 * Corresponds to shared/schemas Python models
 */

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL";

export type FindingStatus =
  | "DETECTED"
  | "SUSPECTED"
  | "VERIFICATION_PENDING"
  | "VERIFIED"
  | "UNVERIFIED"
  | "FALSE_POSITIVE"
  | "RESOLVED"
  | "ACCEPTED_RISK";

export type ScanProfile =
  | "PASSIVE_DISCOVERY"
  | "QUICK_ASSESSMENT"
  | "FULL_ASSESSMENT"
  | "AUTHENTICATED_SCAN"
  | "API_TARGETED"
  | "SAFE_MODE";

export type ScanStatus =
  | "QUEUED"
  | "PRE_FLIGHT"
  | "CRAWLING"
  | "ACTIVE_SCAN"
  | "VERIFYING"
  | "COMPLETED"
  | "FAILED"
  | "PAUSED"
  | "CANCELLED";

export type ScopeRuleType = "INCLUDE" | "EXCLUDE";

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
