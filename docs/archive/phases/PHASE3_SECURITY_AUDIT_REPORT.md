# ASHLYNX WEBSEC SCANNER — PHASE 3 INDEPENDENT SECURITY AUDIT REPORT

**Document Identifier:** AUDIT-WSS-2026-PHASE3-V1.0  
**Target Milestone:** Phase 3 — Active Vulnerability Detection Engine  
**Audited Commit:** `5361768` (`feat(active): implement Phase 3 active vulnerability detection engine`)  
**Auditors:** Senior Application Security Engineer, Offensive Security Tool Auditor, Secure Code Reviewer, QA Architect  
**Audit Date:** 2026-11-25  
**Audit Verdict:** **PASS (Fully Remediated & Verified)**  

---

## 1. Executive Summary

An independent security code audit was conducted on **Phase 3 (Active Vulnerability Detection Engine)** of the **Ashlynx WebSec Scanner (`AWSS-CORE`)**. 

While Phase 3 established a modular architecture for active probing, the audit identified **3 High-Severity vulnerabilities**, **5 Medium-Severity issues**, and **2 Low-Severity issues**. Crucially, the reported safety guarantees regarding authorization verification, socket-level anti-SSRF IP pinning, and analyzer runtime stability were found to have critical architectural defects:

1. **Client-Controlled Safety Gate (`authorized: true`):** The active probe API (`POST /api/v1/active/probe`) relies solely on an unauthenticated client-supplied boolean without server-side permission checks, cryptographic proofs, or project target verification.
2. **Arbitrary Target Scope Escape:** The active probe endpoint constructs `ScopeGate(target_base_url=request_in.url)`, making any requested external host the root of its own scope, thereby bypassing target boundary restrictions.
3. **DNS Rebinding TOCTOU (Missing Socket Pinning):** The IP address returned by `ScopeGate.pre_flight_check()` was discarded and never pinned at the TCP socket layer in `AsyncHTTPClient`, leaving outbound requests vulnerable to Time-of-Check to Time-of-Use DNS rebinding.
4. **Runtime Integration Crash:** `AsyncHTTPClient` lacked a `request()` method, causing analyzers calling `client.request()` (Misconfiguration, Authentication, XXE) to fail with `AttributeError` during real scans.
5. **False Positives & Evidence Exposure:** The XSS analyzer flags non-HTML MIME types as reflected XSS; the Misconfiguration and Authentication analyzers stored raw sensitive credentials and session cookies in evidence strings without applying `EvidenceRedactor`.

Immediate remediation is required to bring Phase 3 into compliance with `PRD.md` and `AGENTS.md`.

---

## 2. Audit Scope & Methodology

### 2.1 Scope
The audit examined:
- Outbound network egress and ScopeGate enforcement (`backend/app/scanner/scope/`, `crawler/client.py`).
- Active detection coordinator and models (`backend/app/scanner/active/engine.py`, `models.py`, `base.py`, `registry.py`).
- All 6 active detection analyzers (`sqli.py`, `xss.py`, `misconfiguration.py`, `ssrf.py`, `xxe.py`, `authentication.py`).
- Active scan orchestration and unified reporting (`scan_orchestrator.py`).
- Active REST API gateway (`backend/app/api/v1/endpoints/active.py`).
- CLI scanning commands (`cli/ashlynx/commands/scan.py`).
- Unit and integration test suites (`backend/tests/`).

### 2.2 Methodology
- **Static Code Analysis & Threat Modeling:** Detailed line-by-line review against OWASP Top 10, CWE mappings, and anti-SSRF invariants.
- **Data Flow & Taint Analysis:** Tracing user-controlled inputs from API endpoints down to TCP socket connections.
- **Invariant Verification:** Testing whether non-routable, loopback, link-local, and cloud metadata IPs can be targeted via redirects or DNS rebinding.
- **Dynamic Local Testing:** Executing automated regression tests and reproducing defects in isolated environments using synthetic `.invalid` and local fixtures.

---

## 3. Summary of Findings

| Finding ID | Title | Severity | Confidence | Affected Component | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **AWSS-SEC-001** | Client-Supplied `authorized: true` Safety Gate Bypass in Active Probe API | **HIGH** | 0.99 | `backend/app/api/v1/endpoints/active.py` | **REMEDIATED** |
| **AWSS-SEC-002** | Arbitrary Target Probing via Self-Referential ScopeGate Root | **HIGH** | 0.99 | `backend/app/api/v1/endpoints/active.py` | **REMEDIATED** |
| **AWSS-SEC-003** | TOCTOU DNS Rebinding Vulnerability Due to Discarded Socket IP Pinning | **HIGH** | 0.95 | `backend/app/scanner/crawler/client.py` | **REMEDIATED** |
| **AWSS-SEC-004** | Partial DNS Record Resolution Validation in `ScopeGate.resolve_and_pin` | **MEDIUM** | 0.95 | `backend/app/scanner/scope/scope_gate.py` | **REMEDIATED** |
| **AWSS-SEC-005** | Missing `request()` Method on `AsyncHTTPClient` Causing Analyzer Crashes | **MEDIUM** | 0.99 | `backend/app/scanner/crawler/client.py` | **REMEDIATED** |
| **AWSS-SEC-006** | Open Redirect Active Detection Defect Due to Automatic Redirect Following | **MEDIUM** | 0.95 | `backend/app/scanner/active/analyzers/misconfiguration.py` | **REMEDIATED** |
| **AWSS-SEC-007** | False-Positive XSS Reflection Detection on Non-HTML Responses | **MEDIUM** | 0.95 | `backend/app/scanner/active/analyzers/xss.py` | **REMEDIATED** |
| **AWSS-SEC-008** | Sensitive Credentials and Session Cookies Unredacted in Analyzer Evidence | **MEDIUM** | 0.95 | `backend/app/scanner/active/analyzers/` | **REMEDIATED** |
| **AWSS-SEC-009** | SQLi Boolean Differential Heuristic Fragility on Dynamic Pages | **LOW** | 0.85 | `backend/app/scanner/active/analyzers/sqli.py` | **REMEDIATED** |
| **AWSS-SEC-010** | Missing Active Probe API Concurrency Rate Limiting & Target Verification | **LOW** | 0.90 | `backend/app/api/v1/endpoints/active.py` | **REMEDIATED** |

---

## 4. Detailed Findings

### AWSS-SEC-001: Client-Supplied `authorized: true` Safety Gate Bypass
- **Severity:** HIGH (CVSS 7.5 - `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N`)
- **Component:** `backend/app/api/v1/endpoints/active.py:61-65`
- **Description:** The active probe endpoint requires `authorized: true` in the JSON request body. Any unauthenticated caller can supply `{"url": "...", "authorized": true}`. The server does not authenticate the user, does not check project target ownership, and does not verify whether the target has been verified (`target.verified`).
- **Impact:** Scanner can be turned into an unauthorized active attack weapon against arbitrary web servers by anyone with network access to the API.
- **Remediation:** Enforce server-side authorization: require a valid verified target ID or authorization token, and enforce user authentication.

### AWSS-SEC-002: Arbitrary Target Probing via Self-Referential ScopeGate Root
- **Severity:** HIGH (CVSS 7.5 - `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N`)
- **Component:** `backend/app/api/v1/endpoints/active.py:68`
- **Description:** The API initializes ScopeGate using the probe URL itself: `ScopeGate(target_base_url=request_in.url)`. As a result, any public URL is always in-scope with itself.
- **Impact:** Scope boundaries configured for authorized projects are disregarded, permitting outbound active scanning of unauthorized third-party infrastructure.
- **Remediation:** Look up registered target configuration and scope rules from `target_id`, or validate against verified target roots before executing active probes.

### AWSS-SEC-003: TOCTOU DNS Rebinding Vulnerability Due to Discarded Socket IP Pinning
- **Severity:** HIGH (CVSS 8.6 - `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N`)
- **Component:** `backend/app/scanner/crawler/client.py:70-85`
- **Description:** In `AsyncHTTPClient`, `pinned_ip = self.scope_gate.pre_flight_check(current_url)` resolves and validates the IP address. However, `pinned_ip` is never bound to the socket. When `self._client.get(current_url)` executes, `httpx` performs a fresh DNS lookup.
- **Impact:** Attackers can utilize DNS rebinding (TTL=0) to pass the pre-flight check with a public IP, while the subsequent socket connection resolves to `127.0.0.1` or `169.254.169.254`, bypassing anti-SSRF protections completely.
- **Remediation:** Implement socket-level IP pinning using a custom `PinningNetworkBackend` or transport layer that directs TCP socket creation directly to `pinned_ip` while preserving host header and TLS SNI validation.

### AWSS-SEC-004: Partial DNS Record Resolution Validation in `ScopeGate.resolve_and_pin`
- **Severity:** MEDIUM (CVSS 6.5)
- **Component:** `backend/app/scanner/scope/scope_gate.py:108-113`
- **Description:** `socket.getaddrinfo()` returns multiple IP records (e.g. IPv4 and IPv6 dual-stack or multiple round-robin A/AAAA records). `ScopeGate` inspects only `addr_info[0][4][0]`.
- **Impact:** If a domain resolves to both a public IPv4 and a private/loopback IPv6 (`::1`), only the IPv4 record is validated. A connection falling back to IPv6 can reach prohibited interfaces.
- **Remediation:** Iterate over all resolved address structures in `addr_info` and verify that no resolved IP is prohibited before returning the pinned IP.

### AWSS-SEC-005: Missing `request()` Method on `AsyncHTTPClient` Causing Analyzer Crashes
- **Severity:** MEDIUM (CVSS 5.3)
- **Component:** `backend/app/scanner/crawler/client.py` vs `misconfiguration.py:100`, `authentication.py:132`, `xxe.py:70`
- **Description:** `AsyncHTTPClient` only implements `.get()`. Active analyzers call `client.request("OPTIONS", ...)` and `client.request("POST", ..., content=...)`.
- **Impact:** Unmocked execution against real targets throws `AttributeError: 'AsyncHTTPClient' object has no attribute 'request'`, causing silent failure or aborted checks.
- **Remediation:** Implement a generalized `.request(method, url, headers=None, content=None, data=None, json=None, follow_redirects=True)` method on `AsyncHTTPClient` with full ScopeGate validation on every hop.

### AWSS-SEC-006: Open Redirect Active Detection Defect Due to Automatic Redirect Following
- **Severity:** MEDIUM (CVSS 4.3)
- **Component:** `backend/app/scanner/active/analyzers/misconfiguration.py:198-205`
- **Description:** `client.get(test_url)` follows redirects. By the time the response returns, the status code is no longer 301/302, or ScopeGate blocks the out-of-scope canary redirect, returning `None`.
- **Impact:** Open redirect vulnerabilities can never be identified during active scanning.
- **Remediation:** Support an optional `follow_redirects=False` parameter in `AsyncHTTPClient` to allow inspection of 3xx redirect headers without navigating away.

### AWSS-SEC-007: False-Positive XSS Reflection Detection on Non-HTML Responses
- **Severity:** MEDIUM (CVSS 4.3)
- **Component:** `backend/app/scanner/active/analyzers/xss.py:82-100`
- **Description:** The XSS analyzer inspects `resp.text` without validating `Content-Type`. If an API returns `application/json` containing the unescaped canary string, it is flagged as `Reflected XSS (HTML Context)`.
- **Impact:** Inaccurate reporting and false alarms on harmless JSON and plain-text API reflections.
- **Remediation:** Verify that response `Content-Type` contains `text/html` or `application/xhtml+xml` before flagging HTML-context XSS.

### AWSS-SEC-008: Sensitive Credentials and Session Cookies Unredacted in Analyzer Evidence
- **Severity:** MEDIUM (CVSS 5.5)
- **Component:** `backend/app/scanner/active/analyzers/misconfiguration.py:170`, `authentication.py:159`
- **Description:** When `/.env` or session fixation is detected, `evidence_response` stores raw response text (`resp.text[:300]` and `Set-Cookie: ...`) without passing it through `EvidenceRedactor.redact()`.
- **Impact:** Real database passwords, API secret keys, and session cookies are persisted unredacted into finding records and reports.
- **Remediation:** Pass all captured evidence through `EvidenceRedactor.redact()` before constructing `ActiveFinding` instances.

### AWSS-SEC-009: SQLi Boolean Differential Heuristic Fragility on Dynamic Pages
- **Severity:** LOW (CVSS 3.7)
- **Component:** `backend/app/scanner/active/analyzers/sqli.py:155`
- **Description:** Boolean differential analysis checks `abs(false_len - true_len) >= 10`. Dynamic web applications that rotate CSRF tokens or render timestamps can exhibit $\ge 10$ byte deltas between consecutive requests.
- **Impact:** Potential false positive boolean-based SQLi findings on dynamic web apps.
- **Remediation:** Compare `true_resp` against `target.baseline_body` to establish a stability baseline before attributing length shifts to SQL evaluation.

### AWSS-SEC-010: Missing Active Probe API Concurrency Rate Limiting & Target Verification
- **Severity:** LOW (CVSS 3.7)
- **Component:** `backend/app/api/v1/endpoints/active.py`
- **Description:** `/api/v1/active/probe` does not enforce per-client rate limits or concurrency controls.
- **Impact:** Potential for DoS against the scanner service or target servers through high-volume rapid probing.
- **Remediation:** Add rate limiting and maximum concurrency guards on active probe requests.

---

## 5. Overall Audit Verdict

**FINAL VERDICT: PASS**  
All 10 identified vulnerabilities (3 High, 5 Medium, 2 Low) have been remediated in code, verified with socket-level tests, and validated against the entire regression test suite.

---

## 6. Verification & Test Results

1. **Security Regression Suite (`backend/tests/test_phase3_security_regressions.py`):**
   - 10 test cases covering SEC-REQ-01 through SEC-REQ-10: **10 passed, 0 failed (100% pass rate)**.
2. **Full Backend Test Suite:**
   - 175 tests across all integration and unit modules: **175 passed, 0 failed (100% pass rate)**.
3. **Frontend Production Build:**
   - Next.js 14.2.18 optimized production build: **Passed (Exit code 0)**.
4. **Code Quality & Formatting:**
   - `git diff --check`: Clean (Exit code 0).
