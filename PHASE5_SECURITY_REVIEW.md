# Ashlynx WebSec Scanner (AWSS-CORE) — Phase 5 Security Review

**Document Version:** 1.0.0  
**Date:** November 25, 2026  
**Reviewer:** Principal Application Security Engineer & Code Auditor  
**Security Verdict:** **PASS — ALL INVARIANTS PRESERVED**

---

## 1. Security Review Scope

This review audited all Phase 5 AVIVE modules, API routes, CLI commands, reporting additions, and frontend views against `PRD.md` and `AGENTS.md` security invariants:
- ScopeGate Anti-SSRF enforcement & test-override isolation
- Authorization & IDOR access control on finding validation/inspection
- Evidence redaction & cryptographic SHA-256 chain of custody
- Two-phase confidence guardrails against false-positive escalation
- Injection/XSS sanitization in reports and UI
- Resource exhaustion safeguards on correlation and pagination

---

## 2. Security Control Verification Results

| Control Area | Verification Evidence | Verdict |
| :--- | :--- | :--- |
| **ScopeGate SSRF Prevention** | `SafeValidationWorkflow.run_safe_revalidation` always instantiates `ScopeGate` respecting `settings.ALLOW_PRIVATE_IPS` (defaults to `False`) and checks `scope_gate.validate_url_in_scope(url)` + socket pinning before sending a bounded GET request via `AsyncHTTPClient`. Direct SSRF to `169.254.169.254` raises `PermissionError` / HTTP `403`. | **PASS** |
| **Mandatory Authorization Gate** | `POST /api/v1/findings/{id}/validate` rejects `run_safe_revalidation=True` unless `authorized=True` is explicitly provided (`403 Forbidden`). | **PASS** |
| **IDOR & Cross-Target Isolation** | `_resolve_finding_with_ownership` verifies optional `scan_id` and `target_id` ownership across `/findings/{id}`, `/relationships`, `/validate`, and `/remediation`, returning `403 Forbidden` on mismatch. | **PASS** |
| **Validation State Integrity** | Finite state machine (`ALLOWED_TRANSITIONS`) rejects invalid transitions (`400 Bad Request`). Automated promotion of `LOW` confidence findings to `VALIDATED` is blocked; `HIGH`/`CRITICAL` findings with `LOW` confidence default to `NEEDS_REVIEW`. | **PASS** |
| **Evidence Redaction & Sealing** | `FindingNormalizer` and `SafeValidationWorkflow` invoke `EvidenceRedactor.redact()` and compute 64-char SHA-256 hashes before persisting request/response or validation support snippets. Verified `Authorization: Bearer` tokens, session cookies, and JSON passwords are masked to `[REDACTED]`. | **PASS** |
| **Stored XSS Defense in Reports** | `HTMLReportGenerator` wraps every AVIVE intelligence field (`root_cause`, `recommended_remediation`, `verification_guidance`, `validation_state`, `contextual_priority`) in `html.escape(..., quote=True)`. Verified in automated test with `<script>alert('xss')</script>`. | **PASS** |
| **Path Traversal Protection** | `ashlynx findings export` delegates output file validation to `ReportManager.validate_and_resolve_output_path()`, blocking `../../etc/passwd` traversal sequences. | **PASS** |
| **Resource Exhaustion Guards** | API pagination caps `page_size` at `100` (`le=100`, rejecting `5000` with `422`), caps query filter string lengths, and uses indexed bucket correlation ($O(N \cdot \text{bucket})$) verified on 500 findings in $< 2\text{s}$. | **PASS** |

---

## 3. Limitations & Security Notes

1. **Workspace Authentication Boundary (MVP / V1 Scope):** In the current single-tenant / single-workspace MVP architecture, finding APIs enforce explicit `target_id` / `scan_id` ownership checks when scoped parameters are supplied. Enterprise RBAC JWT multi-tenancy (PostgreSQL Row-Level Security) remains allocated to V3 per `PRD.md` and `AGENTS.md`.
2. **Test Override Flag:** `ALLOW_PRIVATE_IPS=true` is used strictly in controlled local testing for `http://127.0.0.1:8089`. Code inspection confirmed `Settings.ALLOW_PRIVATE_IPS` and `ScopeGate(allow_private_ips=...)` default strictly to `False`.
3. **Non-Destructive Re-validation Scope:** `run_safe_revalidation` intentionally executes only bounded read-only HTTP checks (`GET`) to confirm reachability and passive header/exposure conditions rather than replaying state-mutating active payloads automatically.
