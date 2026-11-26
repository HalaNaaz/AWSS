# PHASE 3: SECURITY REMEDIATION PLAN

**Document Identifier:** REM-PLAN-WSS-2026-PHASE3-V1.0  
**Parent Report:** `AUDIT-WSS-2026-PHASE3-V1.0`  
**Execution Target:** Phase 3 Remediation Milestone  
**Date:** 2026-11-25  

---

## 1. Prioritized Remediation Tasks

### Task 1 (P0 - Critical): Implement Socket-Level IP Pinning in `AsyncHTTPClient`
- **Finding Ref:** `AWSS-SEC-003`
- **Files Affected:** `backend/app/scanner/crawler/client.py`, `backend/app/scanner/scope/scope_gate.py`
- **Remediation Details:**
  1. Maintain a host-to-IP pin registry (`self.pin_map`) in `AsyncHTTPClient`.
  2. Implement `PinningNetworkBackend` subclassing `httpcore._backends.anyio.AnyIOBackend` that overrides `connect_tcp` to route connections directly to the pinned IP.
  3. Wire `PinningAsyncTransport` into `httpx.AsyncClient` so that all socket connections are pinned at the network layer, preventing TOCTOU DNS rebinding.

### Task 2 (P0 - Critical): Validate All DNS Resolution Records in `ScopeGate`
- **Finding Ref:** `AWSS-SEC-004`
- **Files Affected:** `backend/app/scanner/scope/scope_gate.py`
- **Remediation Details:**
  1. In `ScopeGate.resolve_and_pin()`, loop over all records in `addr_info`.
  2. If any returned IPv4 or IPv6 address is prohibited (loopback, RFC 1918, link-local, cloud metadata), reject with `SSRFValidationError`.
  3. Return the first validated public IP for socket pinning.

### Task 3 (P0 - Critical): Remediate Active Probe Authorization & Scope Enforcement
- **Finding Ref:** `AWSS-SEC-001`, `AWSS-SEC-002`, `AWSS-SEC-010`
- **Files Affected:** `backend/app/api/v1/endpoints/active.py`
- **Remediation Details:**
  1. Update `ActiveProbeRequest` to validate allowed HTTP methods (`GET`, `POST`, `OPTIONS`, `HEAD`).
  2. Do not allow arbitrary client-defined scopes: enforce target URL validation against Target records or require verified target confirmation (`target_id`).
  3. If unverified ad-hoc URL probing is requested, enforce strict hostname restrictions (disallow internal/private IPs, require public routable domains, enforce rate limits).

### Task 4 (P1 - High): Implement Generic `request()` Method on `AsyncHTTPClient`
- **Finding Ref:** `AWSS-SEC-005`, `AWSS-SEC-006`
- **Files Affected:** `backend/app/scanner/crawler/client.py`
- **Remediation Details:**
  1. Add `request(method, url, headers=None, content=None, data=None, json=None, follow_redirects=True)` to `AsyncHTTPClient`.
  2. Enforce pre-flight ScopeGate checks and socket IP pinning on every request.
  3. Support `follow_redirects=False` so that analyzers (like Open Redirect) can safely inspect 3xx `Location` headers without following redirects out-of-scope.

### Task 5 (P1 - High): Redact Sensitive Credentials in Active Finding Evidence
- **Finding Ref:** `AWSS-SEC-008`
- **Files Affected:** `backend/app/scanner/active/analyzers/misconfiguration.py`, `backend/app/scanner/active/analyzers/authentication.py`
- **Remediation Details:**
  1. Pass all `evidence_response` strings in `MisconfigurationAnalyzer` and `AuthenticationAnalyzer` through `EvidenceRedactor.redact()`.
  2. Ensure `.env` passwords and session cookies are masked (`[REDACTED]`).

### Task 6 (P1 - High): Suppress False-Positive XSS Reflections on Non-HTML Responses
- **Finding Ref:** `AWSS-SEC-007`
- **Files Affected:** `backend/app/scanner/active/analyzers/xss.py`
- **Remediation Details:**
  1. Check response `Content-Type` before flagging HTML-context XSS reflections.
  2. Ignore responses with `application/json`, `text/plain`, `application/octet-stream`.

### Task 7 (P2 - Medium): Fix Open Redirect Active Probing Logic
- **Finding Ref:** `AWSS-SEC-006`
- **Files Affected:** `backend/app/scanner/active/analyzers/misconfiguration.py`
- **Remediation Details:**
  1. Use `client.request("GET", test_url, follow_redirects=False)`.
  2. Inspect 3xx status code and `Location` header directly.

### Task 8 (P2 - Medium): Enhance SQLi Boolean Differential Baseline Comparison
- **Finding Ref:** `AWSS-SEC-009`
- **Files Affected:** `backend/app/scanner/active/analyzers/sqli.py`
- **Remediation Details:**
  1. Compare `true_resp` against `target.baseline_body` to detect dynamic pages.
  2. Require that `true_resp` closely resembles baseline while `false_resp` exhibits meaningful structural divergence.

---

## 2. Acceptance Criteria
- Zero test failures across all backend unit and integration tests.
- All 10 security regression tests pass.
- Frontend build compiles cleanly.
- `git diff --check` passes with zero errors.
- Final verdict can be certified as **PASS**.
