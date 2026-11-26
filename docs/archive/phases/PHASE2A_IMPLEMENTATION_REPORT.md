# ASHLYNX WEBSEC SCANNER — PHASE 2A IMPLEMENTATION & VERIFICATION REPORT
## Reconnaissance & Bounded HTTP Crawler Engine

**Product:** Ashlynx WebSec Scanner (`AWSS-CORE`)  
**Parent Specification:** Master PRD v2.0 Final (`PRD-WSS-2026-V2.0-FINAL`)  
**Implementation Phase:** Phase 2A (Reconnaissance & HTTP Crawling)  
**Date:** 24 November 2026  
**Auditor & Engineer:** Senior Python Security Engineer, DAST Architect  
**Status:** COMPLETED & VALIDATED  

---

## 1. Implementation Summary

Phase 2A delivers a complete, modular, and secure attack surface discovery and bounded HTTP crawling engine for Ashlynx WebSec Scanner.

The engine discovers web application pages, internal links, query parameters, passive HTML form metadata, static JavaScript candidate API routes, robots.txt directives, and sitemap.xml URLs. It also performs passive technology fingerprinting across HTTP headers, cookies, and DOM markup.

All network I/O passes through `ScopeGate` for pre-flight domain validation, custom DNS resolution, and socket-level IP pinning, preventing SSRF attacks against RFC 1918 private subnets and cloud metadata (`169.254.169.254`). Every redirect hop is independently validated. In accordance with Phase 2A security restrictions, no form submissions, active vulnerability payloads (SQLi, XSS, SSRF), or state-changing requests are executed.

---

## 2. Modules Created & Files Modified

### 2.1 Core Scanner Subsystems Created
1. **URL Normalization Engine (`backend/app/scanner/crawler/normalizer.py`):**
   - Canonicalizes relative and absolute URLs, collapses duplicate slashes, strips fragments (`#section`), and normalizes default ports (`:80`, `:443`).
   - Deterministically sorts query parameters by key.
   - Rejects prohibited URI schemes (`javascript:`, `mailto:`, `data:`, `tel:`).
   - Identifies and excludes destructive paths (`/logout`, `/delete`, `/signout`, `/destroy`).
   - Classifies endpoints into categories: `PAGE`, `API`, `JAVASCRIPT`, `CSS`, `IMAGE`, `DOCUMENT`, `FORM`, `REDIRECT`, `OTHER`.
2. **Scope-Gated Async HTTP Client (`backend/app/scanner/crawler/client.py`):**
   - Built on `httpx.AsyncClient` with connection pooling, configurable timeouts, and User-Agent customization.
   - Enforces pre-flight ScopeGate checks before request dispatch.
   - Disables automatic redirects (`follow_redirects=False`) to manually validate every redirect destination hop via `ScopeGate.validate_redirect()`.
   - Enforces 5 MB response size limits to protect against content bombs.
   - Handles rate limiting with exponential backoff on HTTP 429.
3. **HTML Parser (`backend/app/scanner/crawler/parser.py`):**
   - Uses `BeautifulSoup` to extract anchor destinations, canonical links, scripts, stylesheets, and meta generator tags.
   - Passively catalogs `<form>` metadata: action URL, method, and input/select/textarea fields without form submission.
4. **Robots & Sitemap Discovery (`backend/app/scanner/reconnaissance/robots_sitemap.py`):**
   - Parses `/robots.txt` for `Disallow`, `Allow`, and `Sitemap` references.
   - Traverses `/sitemap.xml` and sitemap index files recursively up to depth 2.
5. **Passive JavaScript Endpoint Extractor (`backend/app/scanner/reconnaissance/js_analyzer.py`):**
   - Extracts candidate API endpoints from static client `.js` bundles using AST regex patterns (`fetch()`, `axios`, relative `/api/` paths).
   - Validates candidate endpoints against ScopeGate.
6. **Technology Fingerprinting (`backend/app/scanner/fingerprinting/technologies.py`):**
   - Passive technology detection via headers (`Server`, `X-Powered-By`), cookies (`PHPSESSID`, `csrftoken`, `laravel_session`), and HTML DOM generator tags (`WordPress`, `Next.js`, `React`, `Vue.js`).
7. **Bounded Asynchronous Crawler (`backend/app/scanner/crawler/crawler.py`):**
   - Manages visited URL sets, FIFO crawl queue, depth tracking, and concurrency limits via `asyncio.Semaphore`.
   - Halts automatically upon reaching `max_depth`, `max_urls`, or cancellation.
8. **Reconnaissance Orchestrator (`backend/app/scanner/reconnaissance/orchestrator.py`):**
   - Coordinates the discovery pipeline: baseline fingerprinting -> robots/sitemap discovery -> bounded crawl -> static JS analysis -> result aggregation.

### 2.2 Shared Contracts Created & Extended
- `shared/schemas/discovery.py`: Pydantic models for `DiscoveredEndpointCreate`, `DiscoveredEndpointResponse`, `FormMetadataSchema`, `FormFieldSchema`, `TechnologyObservationSchema`, `ReconStartRequest`, `ReconSummaryResponse`.
- `shared/types/models.ts`: Mirrored TypeScript interfaces for frontend and API integration.

### 2.3 Database Models & Migrations
- `backend/app/models/entities.py`: Extended `DiscoveredEndpoint` with normalized URL and category fields; added `DiscoveredForm` and `TechnologyObservation` models.
- `backend/alembic/versions/942c1dc69308_create_phase2a_recon_tables.py`: Alembic migration script for all 12 platform tables.

### 2.4 API Gateway Endpoints (`backend/app/api/v1/endpoints/recon.py`)
- `POST /api/v1/recon/start` — Start authorized reconnaissance job.
- `GET /api/v1/recon/{id}/status` — Retrieve execution summary and metrics.
- `GET /api/v1/recon/{id}/endpoints` — Paginated discovered endpoints.
- `GET /api/v1/recon/{id}/technologies` — Detected technologies and evidence.
- `POST /api/v1/recon/{id}/cancel` — Cancel in-flight job.

### 2.5 CLI Reconnaissance Command (`cli/ashlynx/commands/recon.py`)
- `ashlynx recon --target <url> --authorized [--max-depth 3] [--max-pages 100] [--format table|json]`:
  - Enforces mandatory `--authorized` flag.
  - Passes all requests through ScopeGate.
  - Renders color-coded Rich tables or structured JSON output.

---

## 3. Security Controls & Scope Gate Verification

| Security Control | Implementation Mechanism | Test Assertion | Result |
| :--- | :--- | :--- | :---: |
| **SSRF Prevention** | Pre-flight DNS resolution & IP validation against RFC 1918 / Loopback | `test_crawler_client_blocks_ssrf_loopback` | **PASS** |
| **Cloud Metadata Block** | Explicit check against `169.254.169.254` & `169.254.0.0/16` | `test_crawler_client_blocks_cloud_metadata` | **PASS** |
| **DNS Rebinding Resistance**| Socket IP pinning; connection tied to pre-flight IP | `test_scope_gate_dns_rebinding_resistance` | **PASS** |
| **IPv4-Mapped IPv6 Defense**| Normalizes `::ffff:127.0.0.1` and `::ffff:169.254.169.254` | `test_scope_gate_prohibited_ipv6_and_mapped` | **PASS** |
| **Redirect Gate** | Disables auto-follow; re-checks every redirect hop via ScopeGate | `test_scope_gate_redirect_to_private_subnet` | **PASS** |
| **Scope Lockdown** | Discards out-of-scope domain links before scheduling | `test_crawler_client_blocks_out_of_scope_url` | **PASS** |
| **Destructive URL Safety** | Regex check excluding `/logout`, `/delete`, `/destroy` | `test_url_normalizer_destructive_urls` | **PASS** |
| **Read-Only HTTP Invariant**| Phase 2A only executes GET and HEAD requests | Code review & client assertions | **PASS** |

---

## 4. Test Execution & Verification Matrix

Full test suite executed with `pytest`:

```
============================= test session starts =============================
platform win32 -- Python 3.14.6, pytest-9.1.1, pluggy-1.6.0
rootdir: <PROJECT_ROOT>\backend
configfile: pytest.ini
plugins: anyio-4.14.2, asyncio-1.4.0, cov-7.1.0
collected 35 items

backend\tests\integration\test_crawler.py::test_crawler_multi_page_and_limits PASSED [  2%]
backend\tests\unit\test_evidence_redactor.py::test_evidence_redaction_authorization_headers PASSED [  5%]
backend\tests\unit\test_evidence_redactor.py::test_evidence_redaction_cookies PASSED [  8%]
backend\tests\unit\test_evidence_redactor.py::test_evidence_redaction_json_passwords PASSED [ 11%]
backend\tests\unit\test_evidence_redactor.py::test_evidence_sha256_seal_integrity PASSED [ 14%]
backend\tests\unit\test_health.py::test_health_check_endpoint PASSED     [ 17%]
backend\tests\unit\test_health.py::test_root_liveness_endpoint PASSED    [ 20%]
backend\tests\unit\test_health.py::test_readiness_check_endpoint PASSED  [ 22%]
backend\tests\unit\test_html_parser.py::test_html_parser_links_and_meta PASSED [ 25%]
backend\tests\unit\test_html_parser.py::test_html_parser_form_extraction PASSED [ 28%]
backend\tests\unit\test_js_analyzer.py::test_js_analyzer_endpoint_extraction PASSED [ 31%]
backend\tests\unit\test_normalizer.py::test_url_normalizer_validity PASSED [ 34%]
backend\tests\unit\test_normalizer.py::test_url_normalizer_relative_resolution PASSED [ 37%]
backend\tests\unit\test_normalizer.py::test_url_normalizer_port_and_fragment_removal PASSED [ 40%]
backend\tests\unit\test_normalizer.py::test_url_normalizer_deterministic_query_sorting PASSED [ 42%]
backend\tests\unit\test_normalizer.py::test_url_normalizer_path_collapse PASSED [ 45%]
backend\tests\unit\test_normalizer.py::test_url_normalizer_prohibited_schemes PASSED [ 48%]
backend\tests\unit\test_normalizer.py::test_url_normalizer_destructive_urls PASSED [ 51%]
backend\tests\unit\test_normalizer.py::test_url_normalizer_endpoint_classification PASSED [ 54%]
backend\tests\unit\test_recon_api.py::test_recon_api_lifecycle PASSED    [ 57%]
backend\tests\unit\test_recon_security.py::test_crawler_client_blocks_ssrf_loopback PASSED [ 60%]
backend\tests\unit\test_recon_security.py::test_crawler_client_blocks_cloud_metadata PASSED [ 62%]
backend\tests\unit\test_recon_security.py::test_crawler_client_blocks_out_of_scope_url PASSED [ 65%]
backend\tests\unit\test_recon_security.py::test_scope_gate_redirect_to_private_subnet PASSED [ 68%]
backend\tests\unit\test_robots_sitemap.py::test_robots_txt_parsing PASSED [ 71%]
backend\tests\unit\test_robots_sitemap.py::test_sitemap_xml_parsing PASSED [ 74%]
backend\tests\unit\test_schemas.py::test_scan_job_schema_defaults PASSED [ 77%]
backend\tests\unit\test_schemas.py::test_finding_schema_serialization PASSED [ 80%]
backend\tests\unit\test_scope_gate.py::test_scope_gate_url_in_scope PASSED [ 82%]
backend\tests\unit\test_scope_gate.py::test_scope_gate_prohibited_ipv4_and_metadata PASSED [ 85%]
backend\tests\unit\test_scope_gate.py::test_scope_gate_prohibited_ipv6_and_mapped PASSED [ 88%]
backend\tests\unit\test_scope_gate.py::test_scope_gate_redirect_validation PASSED [ 91%]
backend\tests\unit\test_scope_gate.py::test_scope_gate_dns_rebinding_resistance PASSED [ 94%]
backend\tests\unit\test_technology_fingerprint.py::test_technology_fingerprinting_headers PASSED [ 97%]
backend\tests\unit\test_technology_fingerprint.py::test_technology_fingerprinting_dom_and_meta PASSED [100%]

============================= 35 passed in 2.48s ==============================
```

---

## 5. CLI Verification & Authorization Enforcement

1. **Authorization Gate Test:**
   ```
   $ python -m cli.ashlynx.main recon --target https://example.com
   [!] Target Authorization Required: You must pass --authorized to confirm explicit written consent to assess this target.
   (Exit Code: 1)
   ```
2. **Anti-SSRF Gate Test on CLI:**
   ```
   $ python -m cli.ashlynx.main recon --target http://127.0.0.1:8000 --authorized
   {"level": "WARNING", "name": "ashlynx", "message": "[ScopeGate] Blocked SSRF attempt: 127.0.0.1 -> 127.0.0.1"}
   {"level": "WARNING", "name": "ashlynx", "message": "[AsyncHTTPClient] Security Gate Blocked request to 'http://127.0.0.1:8000/': Anti-SSRF Gate blocked connection to '127.0.0.1' (resolved: 127.0.0.1): IP is within prohibited RFC 1918 / Cloud Metadata CIDR"}
   (Exit Code: 0)
   ```

---

## 6. Known Limitations (Phase 2A Boundary)

1. **Client-Side SPA Execution:** Single-threaded AST regex extraction discovers statically declared routes (`/api/v1/...`, `fetch()`). Complex dynamic DOM routing driven by client-side event handlers is scheduled for Phase 3 (V1) via Playwright headless browser automation.
2. **Passive Crawling Only:** No active injection payloads (SQLi, XSS, SSRF) are fired; forms are inventoried as metadata without automated submission.

---

## 7. Phase Completion Decision

# **VERDICT: PHASE 2A PASSED**

All mandatory Phase 2A requirements, security guardrails, data contracts, and test gates are met. The reconnaissance and bounded HTTP crawling engine is validated and ready for Phase 2B (Active Injection & Two-Phase Verification Modules).
