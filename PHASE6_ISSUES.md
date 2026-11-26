# Ashlynx WebSec Scanner (AWSS-CORE) — Phase 6 Issues & Resolution Log

**Document Version:** 1.0.0  
**Date:** November 26, 2026  
**Resolution Status:** ALL CONFIRMED ISSUES RESOLVED

---

| Issue ID | Component | Severity | Root Cause | Resolution | Status |
| :--- | :--- | :---: | :--- | :--- | :--- |
| **ISSUE-P6-01** | `frontend/app/layout.tsx` & Next.js `.next` cache | **CRITICAL (Blocker)** | Stale running Next.js route manifest / `.next` cache caused `/findings` to fall back to `not-found.tsx` (custom 404) while rendering the shared navbar; navbar also used raw `<a>` tags instead of Next.js `<Link>`. | Upgraded navbar to `<Link>`, cleaned `frontend/.next`, rebuilt cleanly, restarted Next.js, and verified direct URL, `<Link>` click, and `page.reload()` on `/findings` (`200 OK`). | **RESOLVED** |
| **ISSUE-P6-02** | `planner.py`, `context_assessor.py`, `engine.py` | **HIGH** | Discovery helper calls referenced `get_all_parameters()` and `get_apis()` instead of `ParameterIntelligenceEngine.get_parameters()` and `APIDiscoveryEngine.get_api_endpoints()`. | Updated all call sites to canonical `get_parameters()` and `get_api_endpoints()` methods. | **RESOLVED** |
| **ISSUE-P6-03** | `planner.py`, `coverage.py` | **HIGH** | Analyzer ID checks used lowercase aliases (`act_sqli`, `act_xss`) instead of `ActivePluginRegistry` canonical IDs (`ACT-SQLI-ANALYZER`, `ACT-XSS-ANALYZER`, etc.). | Aligned all analyzer IDs across `planner.py`, `coverage.py`, and tests to exact `ACT-*-ANALYZER` identifiers. | **RESOLVED** |
| **ISSUE-P6-04** | `backend/app/scanner/crawler/client.py` | **MEDIUM** | `client.py` had duplicated import blocks at lines 1–24 and lacked `max_retries` + reliability metrics expected by `SafeValidationWorkflow` and Phase 6E. | Deduplicated imports, added bounded `max_retries` (`0..3`) with exponential backoff, and exposed `client.metrics`. | **RESOLVED** |
