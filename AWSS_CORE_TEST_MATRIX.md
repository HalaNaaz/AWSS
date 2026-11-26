# AWSS-CORE — TEST MATRIX

| Category | Suite / Script | Scope | Cases | Passed | Failed | Post-Fix Exit |
|---|---|---|---:|---:|---:|---:|
| Unit & Integration | `pytest backend/tests cli/tests` | Analyzers, ScopeGate, AVIVE, Phase 6, Phase 7, CLI, Reporting | 213 | 213 | 0 | `0` |
| Operational Validation | `pytest tests/operational` | End-to-end live local fixture scan + discovery + reports | 1 | 1 | 0 | `0` |
| Official Browser E2E | `tests/e2e/test_browser_validation.py` | Chrome workflow across `/`, modals, drawer, `/attack-surface`, `/targets`, `/scans`, `/findings`, `/reports` | 8 | 8 | 0 | `0` |
| Audit Browser QA | `audit_evidence/run_browser_audit.py` | All 8 routes, interactions, workflows, 5 viewports × 4 routes, mobile nav, a11y | 44 | 44 | 0 | `0` |
| Audit API / Scanner / CLI / Sec | `audit_evidence/run_backend_api_cli_sec_audit.py` | Live API validation, Phase 7 real `AsyncHTTPClient`, SSRF, Redactor, CLI, Perf | 37 | 37 | 0 | `0` |
| Production Build | `npm.cmd --prefix frontend run build` | TypeScript + ESLint + Next.js static prerendering | 10 | 10 | 0 | `0` |
