# Phase 7 Architecture Review — Advanced Web Security Assessment Expansion

**Project:** Ashlynx WebSec Scanner (`AWSS-CORE`)  
**Phase:** 7A — Pre-Implementation Codebase Analysis & Gap Identification  
**Author:** Security Architecture & Engineering  
**Baseline Commit:** `4db0b1d` (Phases 1–6 Complete)  

---

## 1. Existing Architecture Audit (Phases 1–6)

Before designing Phase 7 extensions, the existing codebase was inspected across all core layers:

| Layer | Existing Components | Verified Capabilities |
| :--- | :--- | :--- |
| **Scope & Safety** | `ScopeGate` (`backend/app/scanner/scope/scope_gate.py`) | Non-bypassable CIDR blocking (RFC 1918, loopback, link-local/IMDS, broadcast/multicast), socket-level IP pinning, redirect validation, `allow_private_ips=False` production default. |
| **HTTP Client** | `AsyncHTTPClient` (`backend/app/scanner/crawler/client.py`) | `PinningTransport`, bounded retries (`0..3`), exponential backoff on HTTP 429/timeouts, request/retry/throttle metrics. |
| **Passive Engine** | `PassiveAnalysisEngine` (`backend/app/scanner/passive/`) | 6 analyzers: `SEC-HDR-ANALYZER`, `COOKIE-SEC-ANALYZER`, `CORS-SEC-ANALYZER`, `INFO-DISC-ANALYZER`, `HTTPS-CFG-ANALYZER`, `HTML-SEC-ANALYZER`. |
| **Active Engine** | `ActivePluginRegistry` (`backend/app/scanner/active/registry.py`) | 6 analyzers: `ACT-SQLI-ANALYZER`, `ACT-XSS-ANALYZER`, `ACT-MISCONFIG-ANALYZER`, `ACT-SSRF-ANALYZER`, `ACT-XXE-ANALYZER`, `ACT-AUTH-ANALYZER`. |
| **Discovery (Phase 4)** | `DiscoveryEngine`, `ParameterIntelligenceEngine`, `APIDiscoveryEngine` | JS AST/endpoint extraction, parameter classification, OpenAPI/GraphQL/REST discovery, attack-surface scoring. |
| **AVIVE (Phase 5)** | `FindingIntelligenceEngine` (`normalizer`, `correlator`, `confidence`, `validation`, `risk_engine`, `remediation`) | Canonical normalization, SHA-256 evidence integrity, deduplication, confidence scoring, contextual risk, remediation guidance. |
| **Intelligence (Phase 6)** | `IntelligentScanPlanner`, `ContextAwareAssessor`, `SecurityCoverageEngine`, `EvidenceIntelligenceEngine`, `SecurityAnalyticsEngine` | Context-aware scan planning, OWASP coverage matrix, reliability telemetry, scan comparison analytics. |

---

## 2. Verified Capability Gaps (Non-Duplication Analysis)

To avoid duplicating Phase 2B, 3, 4, 5, or 6 functionality, each proposed Phase 7 addition was cross-checked against existing `supported_rules`:

### 2.1 Passive Assessment Gaps
1. **Response Caching Security (`SEC-CACHE-ANALYZER`):**
   - Existing `SecurityHeaderAnalyzer` checks CSP, HSTS, XCTO, XFO, Referrer-Policy, and Permissions-Policy, but does **not** evaluate `Cache-Control` or `Pragma` on sensitive/authenticated/API responses (`CWE-524`, `CWE-525`).
2. **JWT & Token Hygiene (`AUTH-TOKEN-ANALYZER`):**
   - Existing `CookieSecurityAnalyzer` inspects `Set-Cookie` flags (`Secure`, `HttpOnly`, `SameSite`, `Max-Age`), and `InformationDisclosureAnalyzer` checks server banners/stack traces/DB URIs, but neither inspects JWT headers/claims (`alg=none`, missing `exp`, sensitive cleartext payload fields) or bearer tokens exposed in response URLs (`CWE-347`, `CWE-613`, `CWE-200`).
3. **Client-Side & DOM Security (`CLIENT-SEC-ANALYZER`):**
   - Existing `HTMLSecurityAnalyzer` checks SRI, charset, viewport, clear-text form actions, form CSRF tokens, and sensitive HTML comments, but does **not** detect `target="_blank"` reverse tabnabbing (`CWE-1022`), dangerous inline DOM source-to-sink patterns (`CWE-79`), `postMessage` wildcard/missing-origin handlers (`CWE-346`), or HTTPS mixed-content resource references (`CWE-319`).

### 2.2 Active Assessment Gaps (Non-Destructive & Bounded)
1. **Path Traversal / LFI Safe Indicator Detection (`ACT-TRAVERSAL-ANALYZER`):**
   - Existing active analyzers cover SQLi, XSS, SSRF, XXE, Misconfig, and Auth, but lack path traversal / local file inclusion (`CWE-22`) checks on file/path/template parameters.
   - Must enforce **Two-Phase Deterministic Verification**: positive OS file marker (`root:x:0:0:`, `[extensions]`) + negative control probe (`ashlynx_nonexistent_...`) to prevent false positives on static error pages.
2. **API Security & Access Control Indicators (`ACT-API-SEC-ANALYZER`):**
   - Existing `APIDiscoveryEngine` discovers API paths, but no active analyzer verifies:
     - Unauthenticated GraphQL introspection (`{__schema{types{name}}}`) (`ACT-API-GRAPHQL-INTROSPECTION`, `CWE-200`)
     - Unauthenticated OpenAPI/Swagger specification exposure (`ACT-API-SWAGGER-EXPOSED`, `CWE-200`)
     - `X-HTTP-Method-Override` / `X-Method-Override` acceptance on safe read probes (`ACT-API-METHOD-OVERRIDE`, `CWE-650`)
     - API Content-Type confusion (JSON endpoint accepting `text/plain` without `415`) (`ACT-API-CONTENT-TYPE-CONFUSION`, `CWE-436`)
3. **Diagnostic Exposure Expansion (`ACT-MISCONFIG-ANALYZER`):**
   - Extend `DIAGNOSTIC_PATHS` conservatively with `/metrics` (Prometheus) and `/server-status` (Apache status) without altering existing misconfiguration rule semantics.

### 2.3 Detection Reliability, Context & Reporting Gaps
1. **Contradictory Evidence & Signal Quality Dampening:**
   - Strengthen `ConfidenceEngine` to dampen confidence when `SUSPECTED` findings have `probe_count <= 1` or lack deterministic secondary verification, and expose optional `signal_quality` (`HIGH`, `MEDIUM`, `LOW`) on `FindingIntelligenceSchema` (backward-compatible default).
2. **Planner, Context Assessor & Coverage Integration:**
   - `IntelligentScanPlanner` and `SecurityCoverageEngine` must recognize `ACT-TRAVERSAL-ANALYZER`, `ACT-API-SEC-ANALYZER`, `SEC-CACHE-ANALYZER`, `AUTH-TOKEN-ANALYZER`, and `CLIENT-SEC-ANALYZER` and map them to OWASP Top 10 categories (`A01:2021`, `A02:2021`, `A03:2021`, `A05:2021`, `A07:2021`).

---

## 3. Non-Negotiable Security & Architectural Constraints

- **ScopeGate Invariant:** Every active probe (`ACT-TRAVERSAL-ANALYZER`, `ACT-API-SEC-ANALYZER`) executes exclusively through `AsyncHTTPClient` backed by `PinningTransport` + `ScopeGate`. `allow_private_ips=False` remains the production default.
- **No Destructive Payloads:** `X-HTTP-Method-Override` tests use safe `HEAD`/`GET` override semantics or benign read checks—never `DELETE`/`PUT` state mutation. Traversal checks read only standard non-destructive markers and never attempt write/execute actions.
- **AVIVE Single Finding Model:** Zero competing finding schemas. All Phase 7 findings emit standard `PassiveFinding` / `ActiveFinding` -> normalized into `FindingResponse` with `FindingIntelligenceSchema`.
- **Evidence Redaction & Hashing:** All captured evidence passes through `EvidenceRedactor` and SHA-256 sealing before persistence or API output.
- **UI Continuity:** No UI redesign. Existing `/findings` and `/analytics` pages surface Phase 7 analyzers, coverage, and signal quality cleanly within the current dark-mode design system.

---

## 4. Prioritized Phase 7 Implementation Plan

1. **Phase 7B (Passive Expansion):** Implement `CacheControlAnalyzer`, `TokenSecurityAnalyzer`, and `ClientSideSecurityAnalyzer`; register in `PassiveAnalysisEngine`.
2. **Phase 7C (Active Expansion):** Implement `PathTraversalAnalyzer` (`ACT-TRAVERSAL-ANALYZER`) and `APISecurityAnalyzer` (`ACT-API-SEC-ANALYZER`); extend `MisconfigurationAnalyzer` diagnostic paths; register in `ActivePluginRegistry`.
3. **Phase 7D–7G (AVIVE, Context, Coverage, Reliability):** Add `signal_quality` dampening in `ConfidenceEngine`, wire new analyzers/categories into `IntelligentScanPlanner`, `ContextAwareAssessor`, `SecurityCoverageEngine`, `RemediationIntelligenceEngine`, and `ScanOrchestrator`.
4. **Phase 7H–7J (API, CLI, Reporting, UI):** Ensure APIs (`/findings`, `/analytics`, `/passive`, `/reports`), CLI (`ashlynx scan`, `ashlynx analytics`), Markdown/JSON reports, and `/findings` + `/analytics` UI surface Phase 7 coverage and signal quality cleanly.
5. **Phase 7K–7O (Verification & Docs):** Unit tests ($\ge 85\%$ coverage), integration tests, security regression tests (ScopeGate, redaction, two-phase verification), operational & live Chrome E2E validation against `http://127.0.0.1:8089`, documentation, and clean git commit.
