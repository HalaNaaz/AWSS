# Ashlynx WebSec Scanner — Phase 6 Test Matrix

**Document Version:** 1.0.0  
**Date:** November 26, 2026  
**Coverage:** **91%** (`backend/app/scanner/intelligence/`)  
**Overall Verdict:** **205 / 205 Backend Tests + Operational + Browser E2E Passed**

---

| Test ID | Suite / File | Test Case / Scope | Verified Assertion | Exit Code | Result |
| :--- | :--- | :--- | :--- | :---: | :---: |
| **P5-REG-01** | `tests/e2e/test_browser_validation.py` | `/findings` 404 Regression Fix | Direct navigation, navbar `<Link>` click, and `page.reload()` return 200 OK and render AVIVE UI | `0` | **PASS** |
| **P6-UNIT-01** | `backend/tests/unit/test_phase6_intelligence.py` | `test_intelligent_scan_planner_prunes_static_and_enforces_scope` | Selects `ACT-SQLI-ANALYZER`, `ACT-XSS-ANALYZER`, `ACT-SSRF-ANALYZER`; prunes `.css`/`.png`; enforces `request_budget` and passive profile | `0` | **PASS** |
| **P6-UNIT-02** | `backend/tests/unit/test_phase6_intelligence.py` | `test_context_aware_assessor_and_coverage_intelligence` | Generates redirect/auth/public-API suggestions; maps OWASP Top 10:2021 honestly (`SKIPPED`, `UNTESTED`, `PARTIAL`, `TESTED`) | `0` | **PASS** |
| **P6-UNIT-03** | `backend/tests/unit/test_phase6_intelligence.py` | `test_http_client_bounded_retry_and_metrics` | Retries transient `429` with backoff and updates `rate_limited_429`, `retried`, `succeeded` counters | `0` | **PASS** |
| **P6-UNIT-04** | `backend/tests/unit/test_phase6_intelligence.py` | `test_evidence_intelligence_and_real_analytics_comparison` | Verifies SHA-256 seals, clean redaction, empty-state analytics (0 fake data), and two-scan fingerprint diff | `0` | **PASS** |
| **P6-INT-01** | `backend/tests/test_phase6_integration_and_security.py` | `test_phase6_orchestrator_api_cli_and_markdown_integration` | Verifies orchestrator populates all Phase 6 schemas, all 7 API endpoints return `200`, Markdown report & CLI analytics succeed | `0` | **PASS** |
| **P6-SEC-01** | `backend/tests/test_phase6_integration_and_security.py` | `test_phase6_security_duplicate_job_guard_and_scopegate_planner` | Duplicate active scan rejected with `409 Conflict`; `ScopeGate` blocks `169.254.169.254` even if injected into discovery | `0` | **PASS** |
| **P6-E2E-01** | `tests/e2e/test_browser_validation.py` | Full Chrome Browser E2E Suite | Verifies all 7 navbar links + `/analytics` 5 tabs + `/findings` AVIVE UI + `/attack-surface` 7 tabs; **0 console errors, 0 failed requests** | `0` | **PASS** |
| **P6-OP-01** | `tests/operational/test_operational_validation.py` | Operational Validation Suite | 39 live operational checks pass against controlled fixture (`127.0.0.1:8089`) | `0` | **PASS** |
| **P6-BLD-01** | `frontend/` (`npm run build`) | Next.js Production Build | All 10 routes compile with TypeScript & lint verification | `0` | **PASS** |
