# AWSS-CORE — FINAL END-TO-END APPLICATION AUDIT REPORT

**Project:** Ashlynx WebSec Scanner (`AWSS-CORE`)  
**Version:** `2.0.0-dev`  
**Audit Date:** 2026-11-26  
**Audit Verdict:** **RELEASE READY WITH ACCEPTED LIMITATIONS**

---

## 1. Executive Summary
Following the **Swiss Technical Grid** UI/UX redesign of Ashlynx WebSec Scanner (`AWSS-CORE`), an end-to-end empirical verification campaign was executed across the running frontend, FastAPI backend, scanner engine, Typer CLI, security invariants, responsive viewports, and regression test suites.

During active execution, the audit uncovered **5 concrete defects** (including 2 High-severity live scanner false-negative bugs in Phase 7 active analyzers, 1 High-severity UI contrast/token bug rendering invisible white-on-transparent links on `/reports` and `not-found.tsx`, 1 Medium API input validation gap on `POST /api/v1/scans/`, and 1 Medium responsive horizontal overflow across `1024px` and `390px` viewports), plus **4 architectural/dependency limitations** (in-memory state without running PostgreSQL/Redis, unauthenticated local workstation API routes, unimplemented SARIF report generator, and `npm audit` advisories in `next@14.2.18`).

All **5 confirmed fixable defects** were patched at root cause, accompanied by regression tests, frontend rebuilds, server restarts, and clean re-verification across `pytest`, live Chrome Playwright QA, CLI, and API integration tests.

---

## 2. Audit Scope
- **Frontend (`frontend/`):** Next.js 14 App Router workstation across all 7 primary routes + custom 404/Error boundaries, Swiss Technical Grid light/dark themes, all buttons/modals/drawers/filters, and 5 responsive viewports (`1920x1080`, `1440x900`, `1024x768`, `768x1024`, `390x844`).
- **Backend & API (`backend/`, `shared/`):** FastAPI REST gateway (`/api/v1/*`), Pydantic validation, middleware headers, CORS, error handling, and in-memory `scan_registry` lifecycle.
- **Scanner Engine:** `ScopeGate` anti-SSRF socket pinning, `AsyncHTTPClient`, 9 passive analyzers, 8 active analyzers, `AttackSurfaceIntelligenceEngine`, `VulnerabilityIntelligenceEngine` (AVIVE), `ReportManager`, and `SecurityAnalyticsEngine`.
- **CLI (`cli/ashlynx/`):** Typer commands, safety gate enforcement, profile validation, and file exports.
- **Security, Performance & Regression:** Non-destructive verification against local controlled test target (`tests/fixtures/controlled_target_app.py`).

---

## 3. Commit and Branch
- **Branch:** `master`
- **Base Commit:** `c3e6c4f77c60b8a37fa47b9646809e90697cf73b`
- **Working Tree State:** Contains the redesigned `frontend/` Swiss Technical Grid UI/UX files, `.gitignore` update (`/reports/`), and audit remediation patches in `backend/app/scanner/active/analyzers/traversal.py`, `backend/app/scanner/active/analyzers/api_security.py`, `shared/schemas/scan.py`, `backend/tests/unit/test_phase7_assessment.py`, `backend/tests/unit/test_scan_api.py`, `frontend/components/app-shell.tsx`, `frontend/app/reports/page.tsx`, `frontend/app/analytics/page.tsx`, `frontend/app/error.tsx`, and `frontend/app/not-found.tsx`.

---

## 4. Application Environment
- **OS:** Windows (`win32`)
- **Python Environment:** `.venv` (`pytest 9.2.0`, `fastapi 0.165.0`, `httpx 0.28.1`, `playwright 1.65.2`, `uvicorn 0.54.0`, `pydantic 2.14.4`)
- **Frontend Environment:** Next.js `15.5.29` (upgraded from `14.2.18` during remediation), React `18.3.1`, Tailwind CSS `3.4.15`, PostCSS `8.5.33`
- **Browser Binary:** Google Chrome (`C:\Program Files\Google\Chrome\Application\chrome.exe`)
- **Controlled Target:** `tests/fixtures/controlled_target_app.py` (`127.0.0.1:8089`, `ALLOW_PRIVATE_IPS=true` explicitly scoped to local test session)

---

## 5. Application Startup Results
| Service | Endpoint / Port | Status | Notes |
|---|---|---|---|
| Controlled Fixture | `http://127.0.0.1:8089/` | **UP (HTTP 200)** | Serves HTML, forms, JS, `/openapi.json`, `/redirect` |
| FastAPI Backend | `http://127.0.0.1:8000/healthz` | **UP (HTTP 200)** | `/api/v1/healthz`, `/api/v1/readyz`, `/api/v1/openapi.json` all HTTP 200 |
| Next.js Frontend | `http://localhost:3000/` | **UP (HTTP 200)** | Production build (`next start`), 10/10 static pages compiled |
| PostgreSQL / Redis | `5432` / `6379` | **NOT RUNNING** | Backend runs via in-memory `scan_registry` |

---

## 6. Route Inventory
All 7 application routes + 404 route verified with live Chrome (`HTTP 200`, `404` for nonexistent route):
- `/` (Dashboard Overview)
- `/targets` (Authorized Target Management)
- `/scans` (Scan Execution Registry)
- `/attack-surface` (Phase 4 Discovery & Topology Graph)
- `/findings` (Phase 5 AVIVE Intelligence & Validation)
- `/analytics` (Phase 6 Telemetry, Coverage, Planner & Comparison)
- `/reports` (HTML/JSON/Markdown Export & Preview)
- `/nonexistent-audit-route` (Custom Swiss Technical 404 Boundary)

---

## 7. Browser Testing Methodology
Automated end-to-end browser verification executed via `audit_evidence/run_browser_audit.py` and `tests/e2e/test_browser_validation.py` against real Chrome (`headless=True`) driving the running Next.js production server and FastAPI backend, coupled with visual inspection of captured PNG screenshots (`audit_evidence/screenshots/`).

---

## 8. Browser QA Results
Post-fix execution (`audit_evidence/logs/browser_audit_after_fixes.txt` & `official_e2e_after_fixes.txt`):
- All 8 tested routes returned expected HTTP status codes (`200` / `404`), loaded CSS (`body` background `rgb(245, 245, 243)`), loaded `Plus Jakarta Sans` / `Space Grotesk` / `IBM Plex Mono`, rendered headings, had `0` broken images, `0` low-contrast buttons (`BrokenContrastBtns=0`), and `0` uncaught `pageerror` exceptions.
- Official Playwright E2E suite passed `8/8` stages (`VERDICT: PASS`, `0` uncaught errors, `0` failed API HTTP requests).

---

## 9. UI Interaction Testing Results
Verified interactive controls in live browser:
- **Theme Toggle:** Switches `Light` (`rgb(245, 245, 243)`) ↔ `Dark` (`rgb(13, 15, 18)`), toggles `.dark` class on `<html>`, persists `awss_theme` in `localStorage` across page reload.
- **Modals & Validation:** Target registration modal empty-name/bad-URL error banners and submission; Scan configuration modal safety-gate (`#auth-check`) error banner, bad-URL rejection, profile dropdown, submission.
- **Drawers & Filters:** Dashboard findings drawer open/severity filter/finding `Details` expand/SHA-256 display/`✕` close; `/findings` AVIVE dropdowns (`Confidence`, `Validation`, `Category`, `Remediation`), `View Details`, `IN_PROGRESS` transition; `/attack-surface` 7 tabs, Endpoints search filter, Zoom In/Out, JSON graph download; `/reports` format dropdown (`html`, `json`, `markdown`), `Preview Report`, `Download` link; `/analytics` 5 tabs and `Compare Scans`.
- **Navigation:** Top navbar links, `Refresh` button on `/scans`, browser `go_back()` / `go_forward()`, and mobile hamburger drawer (`390px`).

---

## 10. Responsive Testing
Tested across 5 viewports (`1920x1080`, `1440x900`, `1024x768`, `768x1024`, `390x844`) across `/`, `/attack-surface`, `/findings`, `/analytics`:
- **Initial run:** Failed at `1024x768` (`scrollWidth=1047`) and `390x844` (`scrollWidth=429..443`).
- **Post-fix run:** **20/20 viewport × route checks passed with `0` horizontal overflow**, and mobile hamburger navigation drawer verified visible & clickable at `390x844`.

---

## 11. Accessibility Results
- Verified semantic landmarks (`header`, `nav`, `main`, `footer`) present on `/`, plus semantic `<nav aria-label="Mobile Navigation">` added for mobile drawer.
- `H1=1`, `UnlabelledBtns=0`, `SelectsWithoutLabel=0`, keyboard `Tab` focus verified (`activeElement` moves cleanly across interactive links/controls with `:focus-visible` outline).
- Post-fix computed contrast on primary CTA links (`Download HTML`, `Compare Scans`, `Return to Overview`) verified as white `#FFFFFF` on Signal Red `rgb(229, 57, 53)`.

---

## 12. Workflow Results
| Workflow | Outcome | Evidence |
|---|---|---|
| A. Target Registration & Validation | **PASS** (UI-only limitation) | Modal validates empty/scheme errors and adds target; reload resets state (in-memory UI state) |
| B. Scan Configuration & Execution | **PASS** | Launches `SAFE_ACTIVE` scan against `127.0.0.1:8089`, polls to `COMPLETED` (91 findings) |
| C. Attack Surface Discovery | **PASS** | All 7 tabs populated (15 endpoints, 9 params, 5 APIs, 1 asset, 129 nodes); JSON export downloads |
| D. Findings & AVIVE Validation | **PASS** | Filters, confidence rationale, remediation, and `IN_PROGRESS` validation transition succeed |
| E. Report Preview & Download | **PASS (Post-fix)** | HTML (`iframe sandbox=""`), JSON, Markdown preview cleanly; `Download` button properly styled |
| F. Analytics & Comparison | **PASS (Post-fix)** | Overview metrics, Planner, OWASP coverage, Reliability, Scan Comparison diff render |

---

## 13. Backend Results
- `pytest backend/tests cli/tests`: **213 passed, 1 warning in 15.73s** (`PYTEST_EXIT=0`, run with `ALLOW_PRIVATE_IPS=false`).
- `pytest tests/operational`: **1 passed in 30.90s** (`OP_EXIT=0`).

---

## 14. API Results
Verified live against `http://127.0.0.1:8000` (`audit_evidence/logs/backend_api_cli_sec_after_fixes.txt`):
- Health/Readiness/OpenAPI (`/healthz`, `/api/v1/healthz`, `/api/v1/readyz`, `/api/v1/openapi.json`): HTTP 200.
- Input Validation (`POST /api/v1/scans/`): Post-fix returns HTTP 422 on `{}`, `""`, `javascript:alert(1)`, `file:///etc/passwd`, `max_urls=0`, `max_urls=99999`.
- Safety Gates (`/api/v1/active/probe`): HTTP 403 when `authorized=False`; HTTP 400 on `PUT`; HTTP 404 on unknown `target_id`.
- Not Found / Bad UUID: HTTP 404 / HTTP 422.
- Gap confirmed: `/api/v1/targets/` returns HTTP 404 (not implemented on backend); `format=sarif` returns HTTP 400.

---

## 15. Scanner Validation Results
- `8` active analyzers and `9` passive analyzers verified registered.
- **High bug discovered & fixed:** `APISecurityAnalyzer` and `PathTraversalAnalyzer` previously threw `TypeError` silently against real `AsyncHTTPClient` (`client.get/post(..., scan_id=...)` and missing tuple unpacking). Post-fix live verification against `AsyncHTTPClient` + `127.0.0.1:8089` detected `ACT-API-SWAGGER-EXPOSED` on `/openapi.json` (`1` finding) and confirmed `PathTraversalAnalyzer` sent `3` HTTP probes.
- Controlled `SAFE_ACTIVE` scan completed in `2.59s` discovering `91` findings (`99` in full E2E context) with deterministic SHA-256 seals.

---

## 16. CLI Results
Executed live via `python -m cli.ashlynx.main`:
- `--help` (`rc=0`), `version` (`rc=0`).
- Safety Gate without `--authorized` rejected (`rc=2`).
- Invalid profile (`rc=2`) and invalid URL (`rc=2`) rejected.
- Controlled `quick-assessment` scan with `-f json -o audit_evidence/logs/cli_scan_report.json` succeeded (`rc=0`) with valid JSON artifact exported.

---

## 17. Security Assessment
- **Anti-SSRF & ScopeGate:** Blocked all 11 tested prohibited IPs (`127.0.0.1`, `10.0.0.1`, `172.16.5.5`, `192.168.1.1`, `169.254.169.254`, `0.0.0.0`, `::1`, `::ffff:127.0.0.1`, `::ffff:169.254.169.254`, `fe80::1`, `fc00::1`) when `allow_private_ips=False`; permitted public IP `93.184.216.34`; blocked out-of-scope redirect (`evil.outside.com`).
- **Headers & CORS:** `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Strict-Transport-Security`, `X-Correlation-ID` enforced; CORS rejects untrusted origins and allows `http://localhost:3000`.
- **XSS / Report Injection:** Static scan found 0 `dangerouslySetInnerHTML`/`innerHTML`/`eval` sinks in `frontend/`; HTML reports escape reflected `<ashxtag>` as `&lt;ashxtag&gt;`; preview `<iframe>` hardened with `sandbox=""`.
- **Evidence Redaction & Path Traversal:** `EvidenceRedactor` masked Bearer tokens, cookies, JSON secrets, `.env` keys, and credit cards; deterministic 64-char SHA-256 seals verified; `ReportManager` blocked `../../evil.json`.
- **Auth & Local Trust Boundary (`SEC-AUTH-01` Remediated):** Backend `HOST` defaults to `127.0.0.1` (`config.py`, `.env.example`), and `LocalBoundaryAndAuthMiddleware` (`security.py`) enforces either constant-time `API_AUTH_TOKEN` (`Authorization: Bearer` / `X-API-Key`) or strict loopback-only access (rejecting non-loopback/forwarded remote clients with HTTP `403`).

---

## 18. Dependency Review
Following remediation of `DEP-NPM-01` (upgrading `next` and `eslint-config-next` to `^15.5.29` and pinning `postcss@^8.5.33`), `npm --prefix frontend audit --json` reports **0 vulnerabilities** (`critical: 0`, `high: 0`, `moderate: 0`, `low: 0`, `FINAL_AUDIT_EXIT=0`). Python `pip-audit` was not installed in `.venv`.

---

## 19. Performance / Reliability Assessment
- Synchronous `SAFE_ACTIVE` controlled scan (`127.0.0.1:8089`, `max_urls=20`): **`2.59s`** (`91` findings).
- Live API response times: `/api/v1/scans/` **`3.58ms`**, `/api/v1/findings/` **`8.24ms`**, `/api/v1/discovery/{id}/graph` **`7.73ms`**, `/api/v1/analytics/overview` **`5.42ms`**.
- `frontend` production build: clean 10/10 static route compilation (`87.1 kB` shared first-load JS).

---

## 20. Regression Test Results
| Suite / Check | Command | Exit Code | Result |
|---|---|---:|---|
| Backend + CLI Pytest (Post-Remediation) | `.venv\Scripts\python.exe -m pytest backend/tests cli/tests -q` | `0` | **214 passed**, 1 warning (`14.97s`) |
| Operational Suite (Post-Remediation) | `.venv\Scripts\python.exe -m pytest tests/operational -q` | `0` | **1 passed**, 6 warnings (`30.15s`) |
| Frontend Prod Build & Lint (`next@15.5.29`) | `npm.cmd --prefix frontend run build` / `lint` | `0` | **10/10 routes** compiled cleanly; 0 ESLint errors |
| Frontend Dependency Audit | `npm.cmd --prefix frontend audit --json` | `0` | **0 vulnerabilities** (`FINAL_AUDIT_EXIT=0`) |
| Official Chrome E2E (Post-Remediation) | `.venv\Scripts\python.exe tests/e2e/test_browser_validation.py` | `0` | **PASS** (0 page errors, 0 failed HTTP) |
| Audit Browser QA | `.venv\Scripts\python.exe audit_evidence/run_browser_audit.py` | `0` | **PASS** (all routes, workflows, 5 viewports) |
| Audit API/Scanner/CLI | `.venv\Scripts\python.exe audit_evidence/run_backend_api_cli_sec_audit.py` | `0` | **37/37 checks passed** (incl. documented expected gaps) |

---

## 21–28. Summary of Findings, Fixes & Remaining Limitations

### Summary Execution Table
| Test Category | Tested | Passed | Failed | Blocked | Not Tested |
|---|---:|---:|---:|---:|---:|
| Browser Routes & Rendering | 8 | 8 | 0 | 0 | 0 |
| UI Interactions & Workflows | 11 | 11 | 0 | 0 | 0 |
| Responsive Viewports (5 × 4) | 20 | 20 | 0 | 0 | 0 |
| Accessibility Checks | 5 | 5 | 0 | 0 | 0 |
| Backend & CLI Unit/Integration (`pytest`) | 214 | 214 | 0 | 0 | 0 |
| Operational Validation (`pytest`) | 1 | 1 | 0 | 0 | 0 |
| Live API / Scanner / CLI / Security Audit | 37 | 37 | 0 | 0 | 0 |
| Official Chrome E2E Validation | 8 | 8 | 0 | 0 | 0 |
| **Total** | **304** | **304** | **0** | **0** | **0** |

### Master Findings Register
| ID | Severity | Category | Finding | Evidence | Status |
|---|---|---|---|---|---|
| `FUNC-SCAN-01` | **High** | Scanner Engine | `APISecurityAnalyzer` passed invalid `scan_id` kwarg & missed `(resp, err)` tuple unpacking on `AsyncHTTPClient`, silently returning 0 findings in live scans. | `audit_evidence/logs/backend_api_cli_sec_audit.json` (pre-fix `0` -> post-fix `1` finding on `/openapi.json`) | **CLOSED** |
| `FUNC-SCAN-02` | **High** | Scanner Engine | `PathTraversalAnalyzer` passed invalid `scan_id` kwarg & missed `(resp, err)` tuple unpacking on `AsyncHTTPClient`, silently sending 0 probes in live scans. | `audit_evidence/logs/backend_api_cli_sec_audit.json` (pre-fix `0` -> post-fix `3` HTTP probes sent) | **CLOSED** |
| `UI-CSS-01` | **High** | UI / Contrast | Non-existent `*-swiss-*` Tailwind classes (`bg-swiss-accent`, `bg-swiss-surface`, `text-swiss-ink`, etc.) caused invisible white-on-transparent links on `/reports`, `/not-found`, and unstyled tabs/cards on `/analytics` and `error.tsx`. | `route_reports.png` pre/post-fix (`BrokenContrastBtns=1` -> `0`; `dl_styles` `rgba(0,0,0,0)` -> `rgb(229,57,53)`) | **CLOSED** |
| `DEP-NPM-01` | **High** | Dependencies | `npm audit` flagged 6 advisories (`next@14.2.18` critical, `postcss`/`glob`/`eslint-config-next` high). | Upgraded to `next@^15.5.29`, `eslint-config-next@^15.5.29`, `postcss@^8.5.33`; `npm_audit_final.json` = `0` vulns | **CLOSED** |
| `API-VAL-01` | **Medium** | API Validation | `POST /api/v1/scans/` accepted `{}` and `javascript:`/`file://` URLs with HTTP 201 instead of 422. | `shared/schemas/scan.py`; `test_create_scan_job_rejects_empty_and_invalid_urls` | **CLOSED** |
| `UI-RESP-01` | **Medium** | Responsive UI | Horizontal overflow at `1024x768` (`scrollWidth=1047`) and `390x844` (`scrollWidth=429..443`) + mobile drawer semantic `<nav>`. | `browser_audit_after_fixes.txt` (`20/20` viewports `overflow=False`, `mobile_390_menu_open.png`) | **CLOSED** |
| `SEC-AUTH-01` | **Medium** | Access Control | Backend defaulted `HOST=0.0.0.0` without local-only boundary or optional API token verification on `/api/v1/*`. | `config.py` (`HOST=127.0.0.1`), `LocalBoundaryAndAuthMiddleware` (`security.py`), `214 passed`, live `403` on forwarded IP | **CLOSED** |
| `ARCH-DB-01` | **Medium** | Persistence | No PostgreSQL/Redis running in local dev; `scan_registry` is in-memory and `/targets` lacks a `/api/v1/targets` backend API (`persisted_across_reload=False`). | `Targets` workflow test (`persisted_across_reload=False`), backend restart check (`[]`), `ScanOrchestrator` failure/cancel verified | **ACCEPTED LIMITATION** |
| `FEAT-SARIF-01` | **Low** | Reporting | `ReportFormat.SARIF` defined in schemas/CLI without a registered `SARIFReportGenerator` (`HTTP 400`). | `GET /api/v1/reports/{id}?format=sarif` -> HTTP 400 | **ACCEPTED LIMITATION** |

---

## 29. Evidence Inventory
- Browser audit script & results: `audit_evidence/run_browser_audit.py`, `audit_evidence/logs/browser_audit_results.json`, `audit_evidence/logs/browser_audit_after_fixes.txt`
- Official E2E log: `audit_evidence/logs/official_e2e_after_fixes.txt`
- Backend/API/Scanner/CLI audit script & logs: `audit_evidence/run_backend_api_cli_sec_audit.py`, `audit_evidence/logs/backend_api_cli_sec_after_fixes.txt`, `audit_evidence/logs/cli_scan_report.json`
- Pytest & Build logs: `audit_evidence/logs/pytest_backend_cli_after_fixes.txt`, `audit_evidence/logs/pytest_operational_after_fixes.txt`, `audit_evidence/logs/frontend_build_after_fixes.txt`, `audit_evidence/logs/npm_audit.json`
- Screenshots: `audit_evidence/screenshots/route_*.png`, `theme_dark_mode.png`, `dashboard_findings_drawer.png`, `mobile_390_menu_open.png`
- Supporting reports: `AWSS_CORE_BROWSER_QA_REPORT.md`, `AWSS_CORE_BACKEND_API_AUDIT.md`, `AWSS_CORE_SECURITY_AUDIT.md`, `AWSS_CORE_SCANNER_VALIDATION.md`, `AWSS_CORE_PERFORMANCE_RELIABILITY_REPORT.md`, `AWSS_CORE_TEST_MATRIX.md`, `AWSS_CORE_FINDINGS_REGISTER.md`, `AWSS_CORE_REMEDIATION_LOG.md`, `AWSS_CORE_RELEASE_READINESS.md`

---

## 30. Release Readiness Verdict
**Verdict:** **RELEASE READY WITH ACCEPTED LIMITATIONS**

All critical and high findings (functional, UI/CSS, security boundary, and npm dependencies) are resolved and verified post-remediation (`0` open Critical/High issues, `0` npm vulnerabilities, `214/214` pytest passing, `E2E_EXIT=0`). The application is ready for authorized single-workstation DAST operation against controlled or authorized targets. Prior to multi-tenant or shared network production deployment, enable persistent PostgreSQL/Redis repository storage, multi-user JWT/RBAC (`V3` roadmap), and register the SARIF report generator.
