# Ashlynx WebSec Scanner (AWSS-CORE) — Phase 6 Security Review

**Document Version:** 1.0.0  
**Date:** November 26, 2026  
**Reviewer:** Security Architect & Application Security Researcher  
**Security Verdict:** **PASS — ZERO SECURITY REGRESSIONS**

---

## 1. Security Controls Audited

1. **ScopeGate Enforcement in Scan Planning (`planner.py`):**
   - `IntelligentScanPlanner.build_plan` evaluates every candidate endpoint via `scope_gate.validate_url_in_scope(url)` before adding it to `planned_checks`.
   - Verified via `test_phase6_security_duplicate_job_guard_and_scopegate_planner`: injecting `http://169.254.169.254/latest/meta-data` into discovery results in explicit rejection in `skipped_checks` (`Excluded by ScopeGate target boundary or SSRF policy`).
   - The planner never expands scope to external domains or unconfigured subdomains.
2. **HTTP Client Reliability & Redirect Safety (`client.py`):**
   - `AsyncHTTPClient` caps `max_retries` to `0..3` (`max(0, min(3, int(max_retries)))`), preventing retry amplification / DoS.
   - `scope_gate.pre_flight_check` and `scope_gate.validate_redirect` remain enforced on every request and redirect hop.
3. **Duplicate Job & Concurrency Guard (`scans.py`, `scan_orchestrator.py`):**
   - `POST /api/v1/scans/` returns `409 Conflict` when an identical `(target_url, profile)` job is already `RUNNING`, preventing resource exhaustion from duplicate submissions.
4. **Evidence Redaction & Chain of Custody (`evidence_intel.py`):**
   - `EvidenceIntelligenceEngine` verifies SHA-256 seal lengths (`64` hex chars) and re-checks `EvidenceRedactor.redact()` invariance across all stored request/response traces.
5. **Honest Coverage & Zero Fabricated Analytics (`coverage.py`, `analytics.py`):**
   - `SecurityCoverageEngine` explicitly marks unobservable categories (`A09:2021`, `A06:2021` SCA, skipped active modules) rather than inflating coverage to 100%.
   - `SecurityAnalyticsEngine` returns empty/zero distributions when no scans exist.

---

## 2. Residual Limitations

- **Authorized Local Fixture Testing:** Browser E2E and CLI live validation used `http://127.0.0.1:8089` with `ALLOW_PRIVATE_IPS=true`; `Settings.ALLOW_PRIVATE_IPS` and `ScopeGate` remain `False` by default.
- **In-Memory Registry Scope:** Analytics and scan comparison operate over scans stored in `ScanLifecycleRegistry` for single-node MVP operation; cross-restart persistence requires PostgreSQL migration in V3.
