# REST API Reference

Base URL: `/api/v1`  
Interactive OpenAPI Docs (when running locally): `http://127.0.0.1:8000/api/v1/docs`

Most endpoints return a standard JSON envelope:
```json
{
  "success": true,
  "message": "Operation completed successfully.",
  "data": {},
  "errors": null
}
```

---

## 1. Health & Readiness
- `GET /healthz` — Root liveness probe (exempt from `API_AUTH_TOKEN`).
- `GET /api/v1/healthz` — Service health metadata.
- `GET /api/v1/readyz` — Readiness probe.

## 2. Authorized Targets (`/api/v1/targets`)
- `GET /api/v1/targets/` — List registered authorized targets and ScopeGate boundaries.
- `POST /api/v1/targets/` — Register an authorized target (`201 Created`); validates `http://`/`https://` scheme and `ScopeGate` IP rules.
- `GET /api/v1/targets/{target_id}` — Fetch single target scope (`404` if not found).
- `DELETE /api/v1/targets/{target_id}` — Delete a registered target.

## 3. Scan Orchestration (`/api/v1/scans`)
- `POST /api/v1/scans/` — Create and run/queue a scan job (`?run_sync=true|false`). Rejects invalid URLs (`422`) and duplicate active scans (`409`).
- `GET /api/v1/scans/` — List tracked scan jobs.
- `GET /api/v1/scans/{scan_id}` — Retrieve scan job status and metrics.
- `POST /api/v1/scans/{scan_id}/cancel` — Cancel a queued or running scan.
- `GET /api/v1/scans/{scan_id}/findings` — Findings detected by the scan.
- `GET /api/v1/scans/{scan_id}/report` — Rendered scan report (`?format=json|html|markdown|sarif`).
- `GET /api/v1/scans/{scan_id}/{plan|context-assessment|coverage|reliability|evidence-intelligence|intelligence}` — Phase 5/6 explainable telemetry endpoints.
- `PUT /api/v1/scans/{scan_id}/risk-config` — Update analyst asset criticality and recalculate contextual priorities.

## 4. Reconnaissance, Passive & Active Analysis
- `POST /api/v1/recon/start`, `GET /api/v1/recon/{id}/status`, `GET /api/v1/recon/{id}/endpoints`, `GET /api/v1/recon/{id}/technologies`, `POST /api/v1/recon/{id}/cancel`
- `GET /api/v1/passive/analyzers`, `GET /api/v1/passive/rules`, `POST /api/v1/passive/analyze`, `GET /api/v1/passive/{scan_id}/findings`
- `GET /api/v1/active/analyzers`, `GET /api/v1/active/rules`, `POST /api/v1/active/probe` *(requires `"authorized": true`, rejects `PUT`/`DELETE`, enforces `ScopeGate`)*

## 5. Attack Surface Discovery (`/api/v1/discovery`)
- `GET /api/v1/discovery/{scan_id}/summary`
- `GET /api/v1/discovery/{scan_id}/endpoints` (supports `category`, `method`, `min_confidence`, `limit <= 5000`, `offset >= 0`)
- `GET /api/v1/discovery/{scan_id}/parameters`
- `GET /api/v1/discovery/{scan_id}/apis`
- `GET /api/v1/discovery/{scan_id}/assets`
- `GET /api/v1/discovery/{scan_id}/graph` (`?graph_format=json|cytoscape`)
- `GET /api/v1/discovery/{scan_id}/prioritized`

## 6. Findings & AVIVE Workflow (`/api/v1/findings`)
- `GET /api/v1/findings/` — Paginated filterable findings (`scan_id`, `target_id`, `severity`, `status`, `confidence_level`, `validation_state`, `cwe_id`, `category`, `asset`, `contextual_priority`, `remediation_status`, `include_duplicates`, `search`).
- `GET /api/v1/findings/{finding_id}` — Detailed finding + redacted evidence + SHA-256 seal.
- `POST /api/v1/findings/{finding_id}/validation` — Transition validation workflow state.
- `PATCH /api/v1/findings/{finding_id}/remediation-status` — Update remediation tracking status.

## 7. Analytics & Report Exports (`/api/v1/analytics`, `/api/v1/reports`)
- `GET /api/v1/analytics/overview` — Multi-scan severity, OWASP coverage, and category analytics.
- `GET /api/v1/analytics/compare?baseline_scan_id=...&current_scan_id=...` — Deterministic finding fingerprint diff between scans.
- `GET /api/v1/reports/{scan_id}?format=json|html|markdown|sarif&download=true|false` — Export/download unified reports (`application/json`, `text/html`, `text/markdown`, `application/sarif+json`).
