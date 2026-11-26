# AWSS-CORE — BACKEND & API AUDIT REPORT

## 1. Test Execution Summary
- **Backend & CLI Suite (`pytest backend/tests cli/tests`):** `213 passed, 1 warning in 15.73s` (`EXIT=0`, `ALLOW_PRIVATE_IPS=false`).
- **Operational Suite (`pytest tests/operational`):** `1 passed, 6 warnings in 30.90s` (`EXIT=0`).
- **Database Status:** PostgreSQL (`5432`) and Redis (`6379`) are not running locally; backend runs cleanly via in-memory `scan_registry`.

## 2. Live API Endpoint Verification (`http://127.0.0.1:8000`)
| Endpoint / Check | Expected | Observed Post-Fix | Status |
|---|---|---|---|
| `GET /healthz`, `/api/v1/healthz`, `/api/v1/readyz`, `/api/v1/openapi.json` | HTTP 200 | HTTP 200 | **PASS** |
| `POST /api/v1/scans/` `{}` (empty payload) | HTTP 422 | HTTP 422 *(pre-fix: 201)* | **PASS (Fixed)** |
| `POST /api/v1/scans/` `javascript:alert(1)` / `file:///etc/passwd` | HTTP 422 | HTTP 422 *(pre-fix: 201)* | **PASS (Fixed)** |
| `POST /api/v1/scans/` `max_urls=0`, `max_urls=99999` | HTTP 422 | HTTP 422 | **PASS** |
| `POST /api/v1/active/probe` (`authorized=False`) | HTTP 403 | HTTP 403 | **PASS** |
| `POST /api/v1/active/probe` (`method="PUT"`) | HTTP 400 | HTTP 400 | **PASS** |
| `POST /api/v1/active/probe` (unknown `target_id`) | HTTP 404 | HTTP 404 | **PASS** |
| `GET /api/v1/scans/{bad-uuid}` / `{missing-uuid}` | 422 / 404 | 422 / 404 | **PASS** |
| `GET /api/v1/reports/{id}?format=sarif` | Supported or explicit error | HTTP 400 (`Unsupported report format: SARIF`) | **KNOWN GAP** |
| `GET /api/v1/targets/` | Target CRUD | HTTP 404 (not implemented on backend) | **KNOWN GAP** |
