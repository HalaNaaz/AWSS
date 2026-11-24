# Phase 3 — Security Test Matrix & Verification Evidence

**Document Identifier:** TEST-MATRIX-WSS-2026-PHASE3  
**Target:** Phase 3 Active Vulnerability Detection Engine  
**Execution Date:** 2026-11-24  
**Status:** ALL TESTS PASSING (133/133)  

---

## 1. Test Suite Coverage Summary

| Module Under Test | Test File | Test Cases | Pass Rate | Key Invariants Verified |
| :--- | :--- | :---: | :---: | :--- |
| **Active Engine Core** | `test_active_engine.py` | 4 | 100% | RequestBudgetTracker limits, registry lookups, profile filtering, cooperative cancellation |
| **SQL Injection** | `test_active_sqli.py` | 3 | 100% | Syntax probe error detection, two-phase boolean invariant verification, safe endpoint handling |
| **XSS Reflection** | `test_active_xss.py` | 3 | 100% | HTML body context reflection, attribute breakout detection, safe escaped reflection suppression |
| **Misconfigurations** | `test_active_misconfiguration.py` | 4 | 100% | Directory listing markers, TRACE method detection, actuator endpoint checks, open redirect detection |
| **SSRF Candidate** | `test_active_ssrf.py` | 2 | 100% | Network error reflection, non-URL parameter exclusion, safe synthetic domain target |
| **XXE Parser Safety** | `test_active_xxe.py` | 2 | 100% | Internal entity expansion reflection, hardened parser handling, no external SYSTEM file calls |
| **Authentication** | `test_active_auth.py` | 2 | 100% | Session ID in URL query, cleartext HTTP auth endpoint detection, zero brute-force attempts |
| **Active REST API** | `test_active_api.py` | 4 | 100% | Analyzer listing, rule catalogue, Safety Gate 403 enforcement, authorized probe execution |
| **Active Integration** | `test_active_integration.py` | 1 | 100% | End-to-end ScanOrchestrator active phase pipeline, finding deduplication, report consolidation |

---

## 2. Security Invariant Verification Details

### 2.1 Scanner Self-Defense & Scope Protection
- **ScopeGate Anti-SSRF:** Verified in `test_scope_gate.py` and `test_active_api.py`. Socket pinning blocks private ranges (`10.0.0.0/8`, `192.168.0.0/16`, `172.16.0.0/12`), loopback (`127.0.0.1`), and cloud metadata (`169.254.169.254`).
- **TOCTOU Rebinding Resistance:** Pinned IP is verified prior to socket connect.

### 2.2 Non-Destructive Payload Verification
- **SQLi Invariant:** Tests use only syntax quotes and `AND 8943=8943` / `AND 8943=8944`. Zero `DROP`, `DELETE`, or `UPDATE` statements are emitted.
- **XSS Invariant:** Tests use only inert canaries (`ashx<token><ashxtag>`). Zero `alert()`, `script`, or DOM-stealing payloads.
- **XXE Invariant:** Tests use local internal entities (`<!ENTITY canary "...">`). Zero `SYSTEM "file://"` or network URL requests.
- **Auth Invariant:** Tests strictly inspect session tokens in query strings and transport security. Zero password guessing or credential stuffing.

### 2.3 Safety Gate Enforcement
- Invoking `ashlynx scan` without `--authorized` / `-a` immediately raises exit code 2.
- Invoking `POST /api/v1/active/probe` without `authorized: true` immediately raises HTTP 403 Forbidden.
