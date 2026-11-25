# PHASE 3 & PHASE 4: REMEDIATION LOG

**Document Identifier:** REM-LOG-WSS-2026-PHASE3-PHASE4-V1.0  
**Audit Reference:** `AUDIT-WSS-2026-PHASE3-PHASE4-V1.0`  
**Date:** 2026-11-25  

---

## 1. Prioritized Remediation Tasks & Implementations

### Finding AWSS-INT-001 (HIGH)
- **Severity:** HIGH
- **Title:** Disallowed HTTP PUT in Active Probe API Allowlist
- **Root Cause:** `backend/app/api/v1/endpoints/active.py` permitted `ALLOWED_PROBE_METHODS = {"GET", "POST", "HEAD", "OPTIONS", "PUT"}`. Allowing `PUT` created a potential risk of unauthorized state modification or resource overwriting on misconfigured servers. No active analyzer requires `PUT`.
- **Affected File:** `backend/app/api/v1/endpoints/active.py`
- **Fix Applied:** Constrained `ALLOWED_PROBE_METHODS = {"GET", "POST", "HEAD", "OPTIONS"}`. Any probe request with method `PUT` (or `DELETE`, `PATCH`, `TRACE`) is immediately rejected with HTTP 400 Bad Request.
- **Regression Test:** `backend/tests/test_phase3_phase4_integration_security.py::test_phase3_probe_prohibits_put_method`
- **Status:** **REMEDIATED (VERIFIED)**

---

### Finding AWSS-INT-002 (HIGH)
- **Severity:** HIGH
- **Title:** Server-Side Target Ownership Validation in Active Probe API
- **Root Cause:** `POST /api/v1/active/probe` relied solely on client-supplied boolean flags without verifying registered target ownership or status.
- **Affected File:** `backend/app/api/v1/endpoints/active.py`
- **Fix Applied:** Integrated target verification when `target_id` is supplied in `ActiveProbeRequest`. If `target_id` is not registered, returns 404. If `not target.verified`, returns 403 Forbidden. If probe URL violates target base URL / scope, returns 400. Documented MVP single-tenant safety boundary.
- **Regression Test:** `backend/tests/test_phase3_phase4_integration_security.py::test_phase3_target_ownership_enforcement`
- **Status:** **REMEDIATED (VERIFIED)**

---

### Finding AWSS-INT-003 (MEDIUM)
- **Severity:** MEDIUM
- **Title:** Missing Discovery Engine Registration in Scan Orchestrator Lifecycle
- **Root Cause:** In `backend/app/scanner/orchestration/scan_orchestrator.py`, `ScanOrchestrator.run()` initialized `ReconOrchestrator` (which creates `discovery_engine`), but never called `scan_registry.register_discovery_engine(self.scan_id, self.discovery_engine)`. As a result, `/api/v1/discovery/{scan_id}/*` endpoints and the Next.js attack surface UI were unable to retrieve full discovery telemetry for active or completed scans.
- **Affected File:** `backend/app/scanner/orchestration/scan_orchestrator.py`
- **Fix Applied:** Added immediate registration of `self._recon_orchestrator.discovery_engine` into `scan_registry` inside `ScanOrchestrator.run()`, making attack surface telemetry available to the API and UI throughout and after the scan lifecycle.
- **Regression Test:** `backend/tests/test_phase3_phase4_integration_security.py::test_phase4_scan_orchestrator_registers_discovery_engine`
- **Status:** **REMEDIATED (VERIFIED)**

---

### Finding AWSS-INT-004 (MEDIUM)
- **Severity:** MEDIUM
- **Title:** Missing Input Size Limit in Static JavaScript Analyzer
- **Root Cause:** `backend/app/scanner/discovery/js_analyzer.py:analyze_js()` processed arbitrarily large JavaScript strings without length constraints, creating a potential ReDoS or memory exhaustion risk on massive (20MB+) or minified bundles.
- **Affected File:** `backend/app/scanner/discovery/js_analyzer.py`
- **Fix Applied:** Introduced `MAX_JS_ANALYSIS_SIZE = 2 * 1024 * 1024` (2 MB) safety cap. Content exceeding 2 MB is sliced safely prior to regex extraction.
- **Regression Test:** `backend/tests/test_phase3_phase4_integration_security.py::test_phase4_js_analyzer_max_size_cap`
- **Status:** **REMEDIATED (VERIFIED)**

---

### Finding AWSS-INT-005 (LOW)
- **Severity:** LOW
- **Title:** Missing Pagination Bounds in Discovery API Endpoints
- **Root Cause:** In `backend/app/api/v1/endpoints/discovery.py`, listing endpoints (`/endpoints`, `/parameters`, `/apis`, `/assets`, `/prioritized`) returned unpaginated arrays, risking performance degradation and UI freezing when scans discover thousands of assets.
- **Affected File:** `backend/app/api/v1/endpoints/discovery.py`
- **Fix Applied:** Added `limit: Optional[int] = Query(default=1000, ge=1, le=5000)` and `offset: Optional[int] = Query(default=0, ge=0)` query parameters across all five discovery list endpoints.
- **Regression Test:** `backend/tests/test_phase3_phase4_integration_security.py::test_phase4_discovery_api_pagination`
- **Status:** **REMEDIATED (VERIFIED)**

---

### Finding AWSS-INT-006 (LOW)
- **Severity:** LOW
- **Title:** Inflexible Finding Node Linkage in Attack Surface Graph
- **Root Cause:** In `backend/app/scanner/discovery/engine.py:321`, `record_finding()` only looked for `ep:{url}:GET` when attaching `HAS_FINDING` edges to endpoint nodes. If an endpoint had method `POST` (e.g. form target), the finding was added to the graph but left disconnected from the endpoint.
- **Affected File:** `backend/app/scanner/discovery/engine.py`
- **Fix Applied:** Enhanced `record_finding()` to check all standard HTTP methods (`GET`, `POST`, `HEAD`, `OPTIONS`, `PUT`, `DELETE`) when resolving the endpoint node ID to create the `HAS_FINDING` edge.
- **Regression Test:** `backend/tests/test_phase3_phase4_integration_security.py::test_phase4_graph_finding_post_method_linkage`
- **Status:** **REMEDIATED (VERIFIED)**
