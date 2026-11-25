# Ashlynx WebSec Scanner — Phase 5 (AVIVE) Test Matrix

**Document Version:** 1.0.0  
**Date:** November 25, 2026  
**Coverage Target:** $\ge 85\%$ (**Achieved: 92%**)  
**Overall Result:** **199 / 199 Backend Tests Passed + Operational + Browser E2E Passed**

---

## 1. Phase 5 Unit & Performance Tests (`backend/tests/unit/test_phase5_intelligence.py`)

| Test ID | Test Case | Component Under Test | Verified Assertion | Result |
| :--- | :--- | :--- | :--- | :--- |
| **P5-UNIT-01** | `test_normalization_across_passive_active_and_malformed_dicts` | `FindingNormalizer` | Normalizes passive, active, and malformed dicts; clamps CVSS/confidence; strips secrets; attaches tech & asset relationships | **PASS** |
| **P5-UNIT-02** | `test_fingerprint_determinism_across_url_variants` | `FindingNormalizer` | Produces identical SHA-256 fingerprint across casing, trailing-slash, and query ordering variations | **PASS** |
| **P5-UNIT-03** | `test_correlation_distinguishes_duplicates_related_systemic_and_independent` | `CorrelationEngine` | Selects verified primary over duplicate; links XSS+CSP as `RELATED`; groups site-wide flaws as `POTENTIALLY_CORRELATED`; isolates `INDEPENDENT` | **PASS** |
| **P5-UNIT-04** | `test_confidence_assessment_separates_high_severity_from_low_confidence` | `ConfidenceEngine` | Assigns `LOW` confidence & `needs_manual_review=True` on WAF-blocked HIGH SQLi; assigns `HIGH` on verified two-phase probe | **PASS** |
| **P5-UNIT-05** | `test_validation_lifecycle_controls_and_risk_separation` | `SafeValidationWorkflow` | Downgrades HIGH+LOW to `NEEDS_REVIEW`; blocks auto-promote; enforces transition matrix; redacts support evidence | **PASS** |
| **P5-UNIT-06** | `test_contextual_risk_reflects_analyst_criticality_without_altering_cvss` | `ContextualRiskEngine` | Score increases with asset criticality while `cvss_baseline` stays immutable at `7.5` | **PASS** |
| **P5-UNIT-07** | `test_remediation_intelligence_cwe_specificity` | `RemediationIntelligenceEngine` | Generates CWE-89 parameterized query remediation, OWASP reference, and parameter component pin | **PASS** |
| **P5-UNIT-08** | `test_correlation_performance_on_large_dataset` | `VulnerabilityIntelligenceEngine` | Normalizes & correlates 500 findings in $< 2.0\text{s}$ | **PASS** |
| **P5-UNIT-09** | `test_safe_revalidation_workflow_header_confirm_and_resolved` | `SafeValidationWorkflow` | Validates non-destructive ScopeGate re-check transitions `VALIDATED` when missing and `RESOLVED` when fixed | **PASS** |

---

## 2. Phase 5 Integration & Security Tests (`backend/tests/test_phase5_integration_and_security.py`)

| Test ID | Test Case | Integration / Security Scope | Verified Assertion | Result |
| :--- | :--- | :--- | :--- | :--- |
| **P5-INT-01** | `test_scan_orchestrator_end_to_end_avive_integration_and_reports` | Orchestrator + AVIVE + Reports | Enriches scan report, redacts tokens, HTML-escapes `<script>` XSS payload in HTML report, populates Markdown & JSON intelligence | **PASS** |
| **P5-INT-02** | `test_api_findings_endpoints_filtering_and_risk_recalculation` | FastAPI `/findings` & `/scans` | Verifies multi-filter `/findings/`, `/relationships`, `/scans/{id}/intelligence`, `/risk-config`, `/remediation` | **PASS** |
| **P5-SEC-01** | `test_security_controls_idor_ssrf_authorization_and_pagination` | Security Controls | Enforces cross-target IDOR `403`, cross-scan validation `403`, unauthorized revalidation `403`, ScopeGate SSRF `PermissionError` (`169.254.169.254`), pagination cap `422` | **PASS** |
| **P5-CLI-01** | `test_cli_findings_commands_and_path_traversal_block` | Typer CLI (`ashlynx findings`) | Validates `list --format json`, safe `export`, and blocks `../../etc/passwd` traversal | **PASS** |
| **P5-DB-01** | `test_phase5_orm_models_instantiation` | SQLAlchemy 2.0 ORM | Validates `CorrelationGroupRecord`, `FindingIntelligenceRecord`, `ValidationHistoryRecord` schemas | **PASS** |

---

## 3. Browser E2E & Live Validation (`tests/e2e/test_browser_validation.py` + CLI + Operational)

| Suite / Command | Exit Code | Key Observations | Result |
| :--- | :---: | :--- | :---: |
| **Backend + Phase 5 Regression Suite** (`pytest backend/tests --cov=...`) | `0` | **199 Passed**, 0 Failed, **92% AVIVE Coverage** | **PASS** |
| **Operational Suite** (`pytest tests/operational`) | `0` | **1 Passed** (39 operational checks) | **PASS** |
| **Browser E2E Suite** (`python tests/e2e/test_browser_validation.py`) | `0` | Tested `/` + `/attack-surface` (7 tabs) + `/targets` + `/scans` + `/findings` (AVIVE summary, 6 filters, expanded panels, remediation state update) + `/reports`; **0 console errors, 0 failed HTTP requests** | **PASS** |
| **CLI Safe-Active Live Scan** (`ashlynx scan http://127.0.0.1:8089 --authorized --profile safe-active --hide-duplicates`) | `0` | 86 normalized findings grouped into 49 unique primary + 37 correlated duplicates | **PASS** |
| **Next.js Production Build** (`npm.cmd --prefix frontend run build`) | `0` | 9 routes built cleanly with TypeScript validation | **PASS** |
