# ASHLYNX WEBSEC SCANNER — PHASE 3 & PHASE 4 OPERATIONAL ISSUES LOG

**Document Version:** 1.0.0  
**Date:** November 25, 2026  
**Auditor:** Principal QA & Security Validation Engineer  
**System:** Ashlynx WebSec Scanner (`AWSS-CORE`)  
**Resolution Status:** ALL CONFIRMED DEFECTS REMEDIATED & RE-VERIFIED  

---

## 1. Defect Summary Table

| Issue ID | Component | Severity | Description | Remediation Summary | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **ISSUE-OP-01** | ScopeGate / ReconOrchestrator | **HIGH** | `ReconOrchestrator` hardcoded `allow_private_ips=False`, preventing local controlled testing | Propagate `settings.ALLOW_PRIVATE_IPS` to `ScopeGate` | **RESOLVED** |
| **ISSUE-OP-02** | Active Scanner API | **HIGH** | `backend/app/api/v1/endpoints/active.py` hardcoded `allow_private_ips=False` for target gate | Update `active.py` to use `settings.ALLOW_PRIVATE_IPS` | **RESOLVED** |
| **ISSUE-OP-03** | Attack Surface Discovery Engine | **MEDIUM** | `ingest_javascript` did not record the JavaScript script itself in `AssetInventoryManager` | Added `self.asset_engine.record_asset(...)` in `ingest_javascript` | **RESOLVED** |
| **ISSUE-OP-04** | Operational Test Harness | **LOW** | Test harness invoked non-existent `get_graph()` method on `AttackSurfaceGraph` | Updated to canonical `to_schema()` method | **RESOLVED** |
| **ISSUE-OP-05** | CLI Output Parsing | **LOW** | CLI stdout included structured log records before JSON output | Enhanced test harness parser to isolate trailing JSON payloads | **RESOLVED** |
| **ISSUE-OP-06** | Test Harness Process Exit | **LOW** | `validator.run_all()` called `sys.exit(0)`, causing pytest to flag `SystemExit` | Made `sys.exit` opt-in via `exit_on_complete` flag | **RESOLVED** |

---

## 2. In-Depth Defect Root Cause Analysis & Remediation

### ISSUE-OP-01: ScopeGate Localhost Setting Propagation in ReconOrchestrator
- **Severity:** High (Functional Block on Authorized Local Test Environments)
- **Component:** `backend/app/scanner/reconnaissance/orchestrator.py`
- **Symptom:**
  When executing a scan against a local test fixture (`http://127.0.0.1:8089`), `ScopeGate` raised an SSRF validation error and halted scanning, even when the environment variable `ALLOW_PRIVATE_IPS=true` was explicitly set.
- **Root Cause:**
  Line 57 of `orchestrator.py` hardcoded `allow_private_ips=False` in `ScopeGate` initialization:
  ```python
  self.scope_gate = ScopeGate(
      target_base_url=self.target_url,
      scope_rules=self.scope_rules,
      allow_private_ips=False  # <--- Defect: Ignored global configuration
  )
  ```
- **Remediation:**
  Imported `settings` from `backend.app.core.config` and bound `allow_private_ips=settings.ALLOW_PRIVATE_IPS`. In production, `settings.ALLOW_PRIVATE_IPS` defaults to `False` (guaranteeing strict SSRF protection against internal subnets and cloud metadata), while in local testing or isolated validation environments, setting `ALLOW_PRIVATE_IPS=true` permits scanning local fixtures.
- **Verification:**
  Tested with `allow_private_ips=False` (confirmed `127.0.0.1` blocked) and `allow_private_ips=True` (confirmed local target allowed).

---

### ISSUE-OP-02: ScopeGate Localhost Setting Propagation in Active Endpoint API
- **Severity:** High (Functional Block on Active Target Probing in Local Environments)
- **Component:** `backend/app/api/v1/endpoints/active.py`
- **Symptom:**
  Calls to `POST /api/v1/active/probe` against `127.0.0.1` failed ScopeGate validation with HTTP 400 despite target verification.
- **Root Cause:**
  Lines 108 and 116 in `active.py` hardcoded `allow_private_ips=False` when constructing `target_gate` and `scope_gate`.
- **Remediation:**
  Updated both `ScopeGate` instantiations in `active.py` to utilize `settings.ALLOW_PRIVATE_IPS`.
- **Verification:**
  Target gate and probe URLs validate correctly when `settings.ALLOW_PRIVATE_IPS=True`.

---

### ISSUE-OP-03: JavaScript Asset Inventory Attachment in Discovery Engine
- **Severity:** Medium (Telemetry Incompleteness)
- **Component:** `backend/app/scanner/discovery/engine.py`
- **Symptom:**
  During live crawling, JavaScript bundles (such as `/static/app.js`) were successfully fetched, parsed for routes/parameters/sourcemaps, and added as graph nodes, but were not recorded in `AssetInventoryManager`. Consequently, `asset_inventory.get_assets()` reported 0 client assets unless HTML direct asset tags were parsed.
- **Root Cause:**
  In `ingest_javascript()`, the engine recorded discovered API routes, query parameters, sourcemaps, and graph nodes, but omitted calling `self.asset_engine.record_asset(...)` for the input `js_url`.
- **Remediation:**
  Added explicit recording in `ingest_javascript()`:
  ```python
  self.asset_engine.record_asset(
      url=js_url,
      content_type="application/javascript",
      size_bytes=len(js_content.encode("utf-8")),
      discovery_source="JS_EXTRACTOR",
      in_scope=True
  )
  ```
- **Verification:**
  Client asset count incremented to $\ge 1$ and `/api/v1/discovery/{id}/assets` correctly returned `/static/app.js` with category `JAVASCRIPT`.

---

### ISSUE-OP-04: Test Harness Graph Schema Method Mismatch
- **Severity:** Low (Test Harness Defect)
- **Component:** `tests/operational/run_operational_validation.py`
- **Symptom:**
  `AttributeError: 'AttackSurfaceGraph' object has no attribute 'get_graph'`.
- **Root Cause:**
  The test script attempted to call `discovery_eng.graph.get_graph()`, but the canonical method in `AttackSurfaceGraph` is `to_schema()`.
- **Remediation:**
  Updated the test call to `discovery_eng.graph.to_schema()`.
- **Verification:**
  Graph schema validated with 124 nodes and 126 edges.

---

### ISSUE-OP-05: CLI Subprocess JSON Output Log Collision
- **Severity:** Low (Test Automation Defect)
- **Component:** `tests/operational/run_operational_validation.py`
- **Symptom:**
  When executing `ashlynx attack-surface --format json` in a subprocess, `json.loads(res.stdout)` raised a `JSONDecodeError`.
- **Root Cause:**
  The root logger writes JSON log records (`{"timestamp": "...", "level": "INFO", ...}`) to `sys.stdout`. The CLI script subsequently printed the JSON data payload to `sys.stdout`. The resulting stdout stream contained multiple newline-separated JSON objects rather than a single document.
- **Remediation:**
  Implemented `extract_trailing_json()` in the operational validation test harness to cleanly isolate and parse the final JSON data payload from preceding log records.
- **Verification:**
  Both `attack-surface --format json` and `--format graph-json` verified valid and schema-conformant.

---

### ISSUE-OP-06: Pytest SystemExit Trap
- **Severity:** Low (Test Runner Incompatibility)
- **Component:** `tests/operational/run_operational_validation.py`
- **Symptom:**
  When running via `pytest tests/operational`, the test failed with `SystemExit: 0`.
- **Root Cause:**
  `run_all()` unconditionally called `sys.exit(0)` on success. In Pytest, unhandled `SystemExit` is treated as a test failure.
- **Remediation:**
  Added `exit_on_complete: bool = False` parameter to `run_all()`. When invoked via pytest, `run_all()` returns `True` or raises an `AssertionError`. When run directly via CLI (`python run_operational_validation.py`), it calls `sys.exit(0)`.
- **Verification:**
  `pytest tests/operational/test_operational_validation.py` passes with exit code 0.
