# Phase 7 Issues & Resolution Log

| ID | Component | Observation | Resolution | Status |
| :--- | :--- | :--- | :--- | :--- |
| P7-01 | `backend/tests/unit/test_active_api.py`, `test_active_engine.py` | Existing unit tests hardcoded `6` active analyzers in `ActivePluginRegistry`. | Updated assertions to `8` and verified `ACT-TRAVERSAL-ANALYZER` and `ACT-API-SEC-ANALYZER` presence. | Resolved |
| P7-02 | `backend/tests/unit/test_phase7_assessment.py` | Initial test draft used `ScopeRuleSchema` / `findings=` kwarg mismatches against existing `ScopeGate` / `VulnerabilityIntelligenceEngine` signatures. | Aligned test calls to `ScopeGate(target_base_url=..., scope_rules=...)` and `VulnerabilityIntelligenceEngine.process_findings(raw_findings=...)`. | Resolved |
| P7-03 | `frontend/app/reports/page.tsx` | Pre-existing React `useEffect` exhaustive-deps lint warning during `next build`. | Non-blocking warning; no regressions introduced in Phase 7. | Tracked (Pre-existing) |
