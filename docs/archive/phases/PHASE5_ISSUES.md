# Ashlynx WebSec Scanner (AWSS-CORE) — Phase 5 Issues & Resolution Log

**Document Version:** 1.0.0  
**Date:** November 25, 2026  
**Resolution Status:** ALL CONFIRMED IMPLEMENTATION & INTEGRATION ISSUES RESOLVED

---

## 1. Issues Discovered & Remediated During Phase 5 Development

| Issue ID | Component | Severity | Symptom / Root Cause | Remediation | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **ISSUE-P5-01** | `backend/app/api/v1/endpoints/passive.py` | **HIGH** | Replacing `_MOCK_FINDINGS` in `findings.py` broke legacy import in `passive.py` during test startup. | Migrated standalone passive finding persistence into `ScanLifecycleRegistry.store_standalone_finding` and enriched `/passive/analyze` via `VulnerabilityIntelligenceEngine`. | **RESOLVED** |
| **ISSUE-P5-02** | `backend/app/scanner/intelligence/remediation.py` | **HIGH** | Missing `Any` typing import on `KNOWLEDGE_BASE: Dict[str, Dict[str, Any]]`. | Added `Any` to `from typing import Any, Dict, List, Optional`. | **RESOLVED** |
| **ISSUE-P5-03** | `cli/ashlynx/commands/findings.py` | **MEDIUM** | `rich.console.Console.print` inserted hard line breaks inside long JSON string values during `ashlynx findings list --format json`, causing `JSONDecodeError`. | Switched JSON output mode to `typer.echo(json.dumps(...))` so stdout remains un-wrapped valid JSON. | **RESOLVED** |
| **ISSUE-P5-04** | `frontend/app/findings/page.tsx` & `page.tsx` | **MEDIUM** | Evidence UI referenced `evidence.response_raw` / `request_raw`, whereas backend `EvidenceSchema` serializes `request` and `response`. | Aligned TypeScript `Finding` model imports (`shared/types/models.ts`) and updated evidence blocks to render `evidence.request` and `evidence.response`. | **RESOLVED** |
| **ISSUE-P5-05** | `frontend/.next` | **LOW** | Stale `.next` build artifacts triggered `PageNotFoundError: Cannot find module for page: /_document` after adding AVIVE pages. | Cleared stale `frontend/.next` cache prior to `next build`, resulting in clean static generation across all 9 routes. | **RESOLVED** |
| **ISSUE-P5-06** | `backend/app/scanner/orchestration/scan_orchestrator.py` | **LOW** | Unimported `Set` annotation in `ScanOrchestrator.__init__` signature (`enabled_modules: Optional[Set[str]]`). | Added explicit `Set` import in `scan_orchestrator.py`. | **RESOLVED** |

---

## 2. Known Non-Blocking Observations

1. **Pydantic V2 / Starlette Deprecation Warnings:** Existing shared schema classes in `shared/schemas/{scope,scan,finding}.py` still use `class Config:` (1 Starlette `httpx` deprecation warning in `backend/tests`, 6 warnings in `tests/operational`). Preserved unmodified outside Phase 5 scope to minimize unrelated diff churn.
2. **ESLint Hook Dependency Notice (`frontend/app/reports/page.tsx:44`):** Pre-existing `react-hooks/exhaustive-deps` warning on the Reports page; does not block Next.js production build or runtime execution.
3. **Database Persistence Runtime:** Phase 5 ORM models (`CorrelationGroupRecord`, `FindingIntelligenceRecord`, `ValidationHistoryRecord`) are added and schema-verified in SQLAlchemy, while live MVP single-node execution uses `ScanLifecycleRegistry` in-memory parity until PostgreSQL worker fleet rollout.
