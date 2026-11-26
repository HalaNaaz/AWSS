# Phase 7 Test Matrix

| Test Suite / Check | Command | Scope & Assertions | Result |
| :--- | :--- | :--- | :--- |
| **Backend Unit & Integration + Coverage** | `pytest backend/tests --cov=backend/app/scanner/intelligence --cov=backend/app/scanner/passive/analyzers --cov=backend/app/scanner/active/analyzers` | 212 tests across Phase 1–7 (including `test_phase7_assessment.py` covering CacheControl, TokenSecurity, ClientSide, PathTraversal two-phase + FP suppression, APISecurity, ScopeGate prod SSRF block, IntelligentScanPlanner, AVIVE, SecurityCoverageEngine) | **212 passed**, **92% coverage** (`cache_control.py` 97%, `client_side.py` 94%, `token_security.py` 92%, `traversal.py` 88%, `api_security.py` 85%) |
| **Operational Validation** | `pytest tests/operational -q` | Full local target workflow against `127.0.0.1:8089` | **1 passed** |
| **Browser E2E QA (Chrome)** | `python tests/e2e/test_browser_validation.py` | Live Chrome UI against `127.0.0.1:3000` + `127.0.0.1:8000` + `127.0.0.1:8089` (0 uncaught page errors, 0 failed HTTP requests, 99 findings, SHA-256 seal, `/findings` AVIVE UI, `/attack-surface` 7 tabs) | **PASS** |
| **Frontend Production Build** | `npm.cmd --prefix frontend run build` | Next.js 14 TypeScript check + production static/SSR build (10 routes) | **Exit 0** |
| **CLI Scan Verification** | `python -m cli.ashlynx.main scan http://127.0.0.1:8089 --profile STANDARD_ACTIVE` (with `ALLOW_PRIVATE_IPS=true`) | End-to-end CLI scan against local controlled fixture | **Verified** |
