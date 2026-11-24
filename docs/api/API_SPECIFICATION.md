# REST API Specification & Contract Catalogue

**Document Identifier:** API-WSS-2026-V1.0  
**Parent Specification:** Master PRD (`PRD-WSS-2026-V2.0-FINAL`)

---

## 1. General API Conventions
- **Base URL:** `/api/v1`
- **Protocol:** HTTPS (TLS 1.3 in production)
- **Content-Type:** `application/json`
- **Authentication:** Bearer JWT in `Authorization` header (`Authorization: Bearer <token>`).
- **Standard Envelope:**
```json
{
  "success": true,
  "message": "Operation completed successfully.",
  "data": {},
  "errors": null
}
```

---

## 2. Core Endpoints Catalogue

### 2.1 System Health & Observability
- `GET /healthz` — Basic root liveness check.
- `GET /api/v1/healthz` — Service health details.
- `GET /api/v1/readyz` — Deep readiness probe (database, redis, security gate).

### 2.2 Scan Job Orchestration
- `POST /api/v1/scans` — Trigger a new scan assessment.
  - **Request Body:**
  ```json
  {
    "target_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "profile": "QUICK_ASSESSMENT",
    "max_crawl_depth": 3,
    "max_urls": 500,
    "concurrency": 5,
    "rate_limit_rps": 10.0
  }
  ```
  - **Response:** `201 Created` with `ScanJobResponse` entity.
- `GET /api/v1/scans/{id}` — Retrieve scan status, crawled URL counter, and finding counts.
- `POST /api/v1/scans/{id}/cancel` — Cancel an in-flight or queued scan job.

### 2.3 Reconnaissance & Attack Surface Discovery (Phase 2A)
- `POST /api/v1/recon/start` — Launch an authorized reconnaissance session.
- `GET /api/v1/recon/{id}/status` — Retrieve execution summary, crawl depth, and status.
- `GET /api/v1/recon/{id}/endpoints` — Paginated list of discovered endpoints with categories and query parameter lists.
- `GET /api/v1/recon/{id}/technologies` — List of detected technologies, versions, confidence scores, and evidence.
- `POST /api/v1/recon/{id}/cancel` — Cancel an in-flight reconnaissance job.

### 2.4 Passive Security Analysis Engine (Phase 2B)
- `GET /api/v1/passive/analyzers` — Lists registered passive security analyzers and capabilities.
- `GET /api/v1/passive/rules` — Lists all supported passive rule identifiers across all analyzers.
- `POST /api/v1/passive/analyze` — Run passive security analysis over observed HTTP request/response transaction.
- `GET /api/v1/passive/{scan_id}/findings` — Retrieve paginated passive findings for a specific scan session.

### 2.5 Vulnerability Findings & Evidence
- `GET /api/v1/findings` — Retrieve paginated findings.
  - **Query Parameters:** `scan_id`, `severity`, `status`, `page`, `page_size`.
  - **Response:** `200 OK` with `PaginatedResponse[FindingResponse]`.
- `GET /api/v1/findings/{id}` — Get single finding with complete redacted HTTP request/response evidence and SHA-256 seal.
- `POST /api/v1/findings/{id}/retest` (V1) — Trigger single-finding verification retest against patched endpoint.

### 2.6 Report Generation & Export (Phase 2C)
- `GET /api/v1/scans/{scan_id}/report` — Retrieve formatted report for a completed scan job.
  - **Query Parameters:** `format` (`json`, `html`, `markdown`, `sarif`). Default: `json`.
  - **Response:** Formatted string content with matching `Content-Type` header (`application/json`, `text/html; charset=utf-8`, `text/markdown; charset=utf-8`).
- `GET /api/v1/reports/{scan_id}` — Export and download security assessment report.
  - **Query Parameters:** `format` (`json`, `html`, `markdown`, `sarif`), `download` (boolean). Default format: `json`.
  - **Response:** Report payload with optional `Content-Disposition: attachment; filename="ashlynx_report_{scan_id}.{ext}"` header.
