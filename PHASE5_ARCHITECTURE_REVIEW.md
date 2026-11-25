# Ashlynx WebSec Scanner (AWSS-CORE) — Phase 5 Architecture & Codebase Review

**Document Version:** 1.0.0  
**Date:** November 25, 2026  
**Author:** Principal Security & Software Architect  
**Target Phase:** Phase 5 — Advanced Vulnerability Intelligence & Validation Engine (AVIVE)  
**Baseline Commit Verified:** `8531223` (`master`)

---

## 1. Executive Summary

This document captures the pre-implementation architectural audit of **Ashlynx WebSec Scanner (AWSS-CORE)** across Phases 1–4 and specifies the integrated architecture for **Phase 5 — Advanced Vulnerability Intelligence & Validation Engine (AVIVE)**.

AVIVE bridges the gap between raw vulnerability detection signals (Phase 2B Passive + Phase 3 Active), structural attack surface telemetry (Phase 4), and security analyst workflows by delivering unified finding normalization, cross-module correlation and deduplication, explainable confidence scoring, controlled validation lifecycles, contextual risk prioritization, and evidence-grounded remediation intelligence.

---

## 2. Existing Architecture & Capabilities (Phases 1–4)

### 2.1 Layer Breakdown
| Layer | Location | Verified Capabilities |
| :--- | :--- | :--- |
| **Shared Contracts** | `shared/schemas/` & `shared/types/models.ts` | Canonical Pydantic v2 models (`Severity`, `FindingStatus`, `ScanStatus`, `FindingResponse`, `UnifiedScanReport`, Discovery schemas) mirrored into TypeScript types. |
| **Scope & Self-Defense** | `backend/app/scanner/scope/scope_gate.py` | Non-bypassable SSRF socket IP pinning (`allow_private_ips=False` default), RFC 1918/Loopback/Cloud Metadata/IPv6-mapped IPv4 blocking, explicit regex `INCLUDE`/`EXCLUDE` scope rules. |
| **Evidence Integrity** | `backend/app/scanner/evidence/redactor.py` | In-memory masking of `Authorization` headers, cookies, credentials, private keys, and credit cards, paired with SHA-256 cryptographic hashes. |
| **Phase 2A/2B Recon & Passive** | `backend/app/scanner/reconnaissance/`, `passive/` | Bounded `AsyncCrawler`, 6 passive analyzers producing sealed `PassiveFinding` records. |
| **Phase 3 Active Engine** | `backend/app/scanner/active/` | 6 non-destructive active analyzers (SQLi, XSS, SSTI/Misconfig, SSRF, XXE, Auth) bounded by `RequestBudgetTracker` and `ScopeGate`. |
| **Phase 4 Discovery** | `backend/app/scanner/discovery/` | 8 subsystems: Endpoint Discovery, JS Static Analyzer, Parameter Intelligence, API Discovery, Asset Inventory, Tech Fingerprinter, Attack Surface Graph, Exploration Prioritizer. |
| **Orchestration** | `backend/app/scanner/orchestration/scan_orchestrator.py` | Coordinates Recon, Passive, Active, and Discovery phases via `ScanLifecycleRegistry` singleton; produces `UnifiedScanReport`. |
| **Reporting** | `backend/app/reporting/` | `ReportManager` generating JSON, HTML (XSS-escaped), and Markdown reports with path-traversal protection. |
| **API Gateway** | `backend/app/api/v1/endpoints/` | FastAPI endpoints for `/scans`, `/discovery`, `/reports`, `/recon`, `/passive`, `/active`, `/findings`, `/healthz`, `/readyz`. |
| **CLI Client** | `cli/ashlynx/` | Typer + Rich CLI (`scan`, `recon`, `attack-surface`, `report`, `version`) sharing core orchestrator directly. |
| **Frontend UI** | `frontend/app/` | Next.js 14 App Router UI (`/`, `/scans`, `/targets`, `/findings`, `/reports`, `/attack-surface`). |

---

## 3. Existing Limitations & Gaps Identified

Direct inspection of the repository revealed specific architectural gaps that Phase 5 addresses:

1. **Naive Cross-Module Deduplication:** `ScanOrchestrator.run()` currently deduplicates combined passive and active findings solely by `(f.title, url, param)` (lines 239–248). It cannot correlate related findings with different titles, differing HTTP methods, or passive vs. active observations pointing to the same root weakness.
2. **Disconnected `/api/v1/findings` Router:** `backend/app/api/v1/endpoints/findings.py` uses an empty in-memory `_MOCK_FINDINGS` dictionary instead of reading live findings from `scan_registry`, leaving `/api/v1/findings/` non-functional for live scan data.
3. **Opaque Scalar Confidence:** `FindingResponse.confidence` is a bare float (`0.0–1.0`) with no breakdown explaining which detection method, corroboration, response consistency, or missing evidence produced the score, and no explicit `LOW`/`MEDIUM`/`HIGH` confidence classification.
4. **Absence of Contextual Risk Assessment:** Findings rely solely on static CVSS scores and severity labels. They are disconnected from Phase 4 telemetry (endpoint auth boundaries, parameter sensitivity, API exposure, technology observations, asset criticality, and related vulnerability clusters).
5. **Flat Remediation Text:** Remediation is a single unformatted string rather than structured guidance covering root cause, impact, affected component, technology-aware secure implementation, non-destructive verification guidance, OWASP/CWE mapping, and priority.
6. **No Traceable Validation Lifecycle:** While `FindingStatus` contains statuses such as `SUSPECTED` and `VERIFIED`, there is no state machine enforcing valid transitions, tracking validation history/actors/timestamps, or preventing invalid overrides (e.g., auto-validating a `HIGH` severity / `LOW` confidence finding).
7. **Frontend Evidence Field Mismatch:** `frontend/app/findings/page.tsx` and `frontend/app/page.tsx` read `f.evidence.response_raw`, whereas `EvidenceSchema` on the backend serializes `request` and `response`.

---

## 4. Phase 5 (AVIVE) System Architecture

AVIVE is implemented as an integrated backend engine under `backend/app/scanner/intelligence/` with Risk Context utilities exposed through `backend/app/risk/` and shared contracts in `shared/schemas/intelligence.py`.

### 4.1 Component Architecture & Responsibilities

```
+-----------------------------------------------------------------------------+
|                    ScanOrchestrator / ScanLifecycleRegistry                 |
+-----------------------------------------------------------------------------+
       | (Passive + Active Findings)                ^ (Attack Surface Telemetry)
       v                                            |
+-----------------------------------------------------------------------------+
|         VulnerabilityIntelligenceEngine (AVIVE Master Coordinator)          |
|                                                                             |
|  1. FindingNormalizer (Phase 5B)                                            |
|     - Canonicalizes PassiveFinding / ActiveFinding / FindingResponse / dict  |
|     - Validates fields, computes deterministic finding fingerprint           |
|     - Links endpoint, parameter, asset, and technology relationships         |
|                                                                             |
|  2. CorrelationEngine (Phase 5C)                                            |
|     - Groups duplicates, related, potentially correlated, & independent     |
|     - Computes correlation confidence & explicit rationale                  |
|     - Selects deterministic primary finding without discarding originals    |
|                                                                             |
|  3. ConfidenceEngine (Phase 5D)                                             |
|     - Evaluates method reliability, reproducibility, completeness, signal   |
|       quality, response consistency, contradictions & corroboration         |
|     - Assigns LOW / MEDIUM / HIGH classification + needs_manual_review      |
|                                                                             |
|  4. SafeValidationWorkflow (Phase 5E)                                       |
|     - Enforces controlled state transitions & immutable audit history       |
|     - Optional bounded safe re-validation strictly via ScopeGate            |
|                                                                             |
|  5. ContextualRiskEngine (Phase 5F -> backend/app/risk/)                    |
|     - Separates CVSS, Severity, Confidence, & Contextual Priority           |
|     - Evaluates auth exposure, asset criticality, tech & cluster context    |
|     - Reports explicit Data Limitations when asset criticality is unset     |
|                                                                             |
|  6. RemediationIntelligenceEngine (Phase 5G)                                |
|     - Produces CWE/OWASP-grounded, component-specific remediation plans     |
+-----------------------------------------------------------------------------+
       |
       +--> UnifiedScanReport (enriched findings + intelligence summary)
       +--> FastAPI Gateway (/api/v1/findings/*, /api/v1/scans/*)
       +--> ReportManager (JSON, HTML, Markdown backward-compatible + enriched)
       +--> Typer + Rich CLI (`ashlynx scan`, `ashlynx findings`)
       +--> Next.js Frontend (`/findings`, `/`, `/reports`)
```

### 4.2 Data Flow & Backward Compatibility
1. `ReconOrchestrator` collects endpoints, parameters, APIs, assets, technologies, and `PassiveFinding` records.
2. `ActiveDetectionEngine` (when enabled by profile) runs non-destructive bounded active probes via `ScopeGate`-pinned `AsyncHTTPClient` and produces `ActiveFinding` records.
3. `ScanOrchestrator` invokes `VulnerabilityIntelligenceEngine.process_scan_findings(...)` passing raw findings, `AttackSurfaceIntelligenceEngine` context, `target_id`, and optional analyst `asset_criticality`.
4. Each `FindingResponse` retains every existing Phase 1–4 top-level attribute (`id`, `scan_id`, `title`, `cwe_id`, `severity`, `cvss_score`, `status`, `confidence`, `remediation`, `endpoint`, `evidence`, `created_at`) while attaching an optional `intelligence: Optional[FindingIntelligenceSchema]` payload and updating `UnifiedScanReport` with `intelligence_summary` and `correlation_groups`.
5. Existing API consumers, JSON/HTML/Markdown reports, and Phase 1–4 tests continue working identically, while Phase 5 consumers gain full structured intelligence.

### 4.3 Database & Persistence Considerations
- **SQLAlchemy Entities (`backend/app/models/entities.py`):** Extended cleanly with `FindingIntelligenceRecord` / `CorrelationGroupRecord` / `ValidationHistoryRecord` schemas mapped to `Finding` and `ScanJob` for PostgreSQL migration readiness, while maintaining `ScanLifecycleRegistry` in-memory parity for MVP/single-node runtime without forcing external database startup dependencies during unit or CI runs.
- **Migration Strategy:** All new ORM columns/tables are additive (`nullable=True` or separate linked tables with `ON DELETE CASCADE`), requiring zero breaking modifications to existing tables.

### 4.4 API & CLI Integration
- **REST API (`backend/app/api/v1/endpoints/findings.py` & `scans.py`):**
  - `GET /api/v1/findings/`: Connected to `scan_registry` and AVIVE store with full filtering (`scan_id`, `target_id`, `severity`, `confidence_level`, `validation_status`, `cwe_id`, `asset`, `correlation_group_id`, `remediation_priority`, `include_duplicates`) and safe pagination.
  - `GET /api/v1/findings/{finding_id}`: Returns full normalized finding + AVIVE intelligence, correlation links, and validation history.
  - `POST /api/v1/findings/{finding_id}/validate`: Analyst-triggered state transition or safe non-destructive re-validation through `ScopeGate` (enforces target authorization, scope validation, and valid transition rules).
  - `GET /api/v1/scans/{scan_id}/intelligence`: Returns scan-level correlation groups, confidence breakdown, contextual risk distribution, and prioritized remediation queue.
  - `POST /api/v1/scans/{scan_id}/risk-config`: Allows analysts to configure `asset_criticality` (`0.5–5.0`) and dynamically recalculate contextual risk scores without modifying CVSS.
- **CLI (`cli/ashlynx/commands/findings.py` & `scan.py`):**
  - Enriches `ashlynx scan` output tables with Confidence Level, Contextual Priority, Correlation Group badge, and Validation Status.
  - Adds `ashlynx findings` subcommands (`list`, `inspect`, `export`, `validate`) supporting filtering by severity, confidence, validation state, correlation group, and enriched JSON export.

### 4.5 Security Boundaries
- **ScopeGate Non-Bypassable Egress:** Safe re-validation checks always instantiate `AsyncHTTPClient` bound to `ScopeGate` with `settings.ALLOW_PRIVATE_IPS` policy (default `False`). No direct `httpx` calls bypassing `ScopeGate` are permitted.
- **No Destructive Validation:** Validation probes strictly reuse non-destructive mathematical invariants, inert XSS canaries, or read-only header verification.
- **IDOR & Cross-Target Isolation:** Validation updates and finding lookups verify `scan_id` / `target_id` ownership context when supplied and reject malformed UUIDs, unknown state transitions, and excessive pagination limits.
- **Evidence Redaction Preservation:** Re-validation responses pass through `EvidenceRedactor.redact()` and `EvidenceRedactor.generate_sha256_seal()` before storage or display.

---

## 5. Testing Strategy

1. **Unit Tests:** Normalization of valid/malformed/passive/active findings, deterministic fingerprinting, duplicate vs. related vs. independent correlation, explainable confidence edge cases (HIGH severity + LOW confidence), validation state transition machine, contextual risk weighting & data limitations, remediation knowledge coverage.
2. **Integration Tests:** End-to-end `ScanOrchestrator` + `AttackSurfaceIntelligenceEngine` + `VulnerabilityIntelligenceEngine` pipeline, FastAPI `/api/v1/findings` & `/scans/{id}/intelligence`, JSON/HTML/Markdown reporting, CLI `scan` and `findings` invocations.
3. **Security Tests:** Unauthorized validation blocking, `ScopeGate` SSRF blocking during re-validation, cross-target isolation/IDOR guards, invalid transition rejection, malformed finding injection resistance, secret redaction in enriched payloads, resource limits on correlation/pagination.
4. **Browser E2E Tests:** Playwright + Chrome tests on `/findings` and `/` validating confidence badges, validation status, correlation groups, contextual priority, filters, detail view, remediation intelligence, and API/UI parity against the controlled local fixture (`http://127.0.0.1:8089`).
