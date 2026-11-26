# AWSS-CORE — BROWSER QA & RESPONSIVE AUDIT REPORT

**Browser:** Google Chrome (`C:\Program Files\Google\Chrome\Application\chrome.exe`) via Playwright  
**Target URL:** `http://localhost:3000` (Next.js `14.2.18` production build)

## 1. Route Rendering Matrix
| Route | HTTP Status | Canvas BG (Light) | Broken Contrast Btns | Page Errors | Result |
|---|---:|---|---:|---:|---|
| `/` | 200 | `rgb(245, 245, 243)` | 0 | 0 | **PASS** |
| `/targets` | 200 | `rgb(245, 245, 243)` | 0 | 0 | **PASS** |
| `/scans` | 200 | `rgb(245, 245, 243)` | 0 | 0 | **PASS** |
| `/attack-surface` | 200 | `rgb(245, 245, 243)` | 0 | 0 | **PASS** |
| `/findings` | 200 | `rgb(245, 245, 243)` | 0 | 0 | **PASS** |
| `/analytics` | 200 | `rgb(245, 245, 243)` | 0 | 0 | **PASS (Post-fix)** |
| `/reports` | 200 | `rgb(245, 245, 243)` | 0 *(was 1)* | 0 | **PASS (Post-fix)** |
| `/nonexistent-audit-route` | 404 | `rgb(245, 245, 243)` | 0 *(was 1)* | 0 | **PASS (Post-fix)** |

## 2. Interactive Controls & Workflow Verification
- **Theme Toggle:** Light (`rgb(245, 245, 243)`) ↔ Dark (`rgb(13, 15, 18)`), `awss_theme` persisted in `localStorage` across reload.
- **Dashboard (`/`):** `+ New Scan` and `Register Target` modals validate empty names, invalid schemes, and `#auth-check` safety gate; scan polls to `COMPLETED`; `Findings` drawer opens (`91`–`99` findings), filters severity, expands `Details`, verifies 64-char SHA-256 seal and Remediation Guidance, closes via `✕`.
- **Targets (`/targets`):** `+ Add Target` modal works in UI; reload confirms state is client-only (`persisted_across_reload=False`).
- **Scans (`/scans`):** Orchestrator table + `Refresh` + `Surface`/`Findings` links functional.
- **Attack Surface (`/attack-surface`):** All 7 tabs (`Overview & Signals`, `Prioritization Queue`, `Endpoints`, `Parameters`, `APIs`, `Assets`, `Topology Graph`), Endpoints filter, `Zoom In`/`Zoom Out`, and `Export Graph JSON` verified.
- **Findings (`/findings`):** AVIVE metrics, all filter dropdowns (`Confidence`, `Validation`, `Category`, `Correlation`, `Remediation`), `View Details`, and `IN_PROGRESS` transition verified.
- **Reports (`/reports`):** HTML (`iframe sandbox=""`), JSON, and Markdown previews verified; `Download HTML` Signal-Red button contrast (`rgb(229, 57, 53)` / `#FFFFFF`) verified post-fix.
- **Analytics (`/analytics`):** All 5 tabs + `Compare Scans` diff summary verified post-fix.
- **Official E2E Suite (`tests/e2e/test_browser_validation.py`):** **PASS** (`0` uncaught errors, `0` failed API HTTP requests).

## 3. Responsive & Accessibility Matrix
- **Viewports Tested:** `1920x1080`, `1440x900`, `1024x768`, `768x1024`, `390x844` across `/`, `/attack-surface`, `/findings`, `/analytics`.
- **Pre-fix Defect:** Horizontal overflow detected on all 4 routes at `1024x768` (`scrollWidth=1047`) and `390x844` (`scrollWidth=429..443`).
- **Post-fix Result:** **20/20 checks passed with `overflow=false`**. Mobile hamburger `<nav aria-label="Mobile Navigation">` verified openable and clickable at `390px`.
- **Accessibility:** `header`, `nav`, `main`, `footer` landmarks present; `H1=1`; `UnlabelledBtns=0`; `SelectsWithoutLabel=0`; keyboard `Tab` focus verified.
