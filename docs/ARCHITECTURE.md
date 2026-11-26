# System Architecture & Technical Reference

Ashlynx WebSec Scanner (`AWSS`) is an OWASP-aligned Dynamic Application Security Testing (DAST), attack surface discovery, and vulnerability verification platform structured around a unified Python core engine, FastAPI gateway, Next.js workstation UI, and Typer CLI.

---

## 1. Subsystem Overview

```
CLI (Typer) / Web Workstation (Next.js 15)
        │
        ▼ REST (/api/v1) + LocalBoundaryAndAuthMiddleware
FastAPI Gateway (backend/app/api/v1)
        │
        ▼ ScanOrchestrator + ScanLifecycleRegistry
  ┌─────────────────────────────────────────────────────────────┐
  │ Recon & Async Crawler  ──▶  ScopeGate Anti-SSRF Pinning     │
  │ Passive Analyzers (9)  ──▶  JS Static AST Intelligence      │
  │ Active Analyzers (8)   ──▶  Two-Phase Verifier & Budget     │
  │ Attack Surface Engine  ──▶  AVIVE Correlation & Risk Engine │
  │ EvidenceRedactor + SHA-256  ──▶ ReportManager (JSON/HTML/MD/SARIF)
  └─────────────────────────────────────────────────────────────┘
```

### Core Packages (`backend/app/`)
- **`api/v1/`:** Typed REST endpoints for health/readiness, authorized targets (`/targets`), scan orchestration (`/scans`), reconnaissance (`/recon`), passive analysis (`/passive`), active probing (`/active`), discovery (`/discovery`), findings/AVIVE (`/findings`), analytics (`/analytics`), and reporting (`/reports`).
- **`middleware/`:** `SecurityHeadersMiddleware`, `CorrelationIdMiddleware`, `CORSMiddleware`, and `LocalBoundaryAndAuthMiddleware` (enforcing `127.0.0.1` loopback boundary and optional `API_AUTH_TOKEN` Bearer/`X-API-Key` validation).
- **`scanner/scope/`:** `ScopeGate` non-bypassable URL scope checker, DNS resolver, private/CGNAT/metadata CIDR blocklist, and socket-level IP pinning.
- **`scanner/crawler/`:** Bounded asynchronous `AsyncHTTPClient` (`PinningNetworkBackend`), URL normalizer, HTML parser, and `robots.txt`/sitemap ingestion.
- **`scanner/passive/` & `scanner/active/`:** 9 passive analyzers (headers, cookies, CORS, disclosure, transport, HTML DOM, cache-control, JWT/tokens, client-side risks) and 8 non-destructive active analyzers (SQLi boolean invariant, reflected XSS canary, SSRF probe, XXE probe, misconfigurations, path traversal, auth/session flaws, API security) bounded by `RequestBudgetTracker`.
- **`scanner/discovery/` & `scanner/intelligence/`:** Attack surface topology graph (JSON/Cytoscape), parameter/API/asset/tech discovery engines, AVIVE correlation/confidence/contextual risk/validation FSM, intelligent scan planner, OWASP Top 10 coverage metrics, and scan comparison analytics.
- **`scanner/evidence/` & `reporting/`:** `EvidenceRedactor` + SHA-256 chain-of-custody seals, paired with `JSONReportGenerator`, `HTMLReportGenerator`, `MarkdownReportGenerator`, and `SARIFReportGenerator` (`application/sarif+json`).

---

## 2. Technology Stack

| Layer | Technology | Role |
|---|---|---|
| Backend & Engine | Python 3.11+ (`FastAPI`, `HTTPX`, `Pydantic v2`, `BeautifulSoup4`) | Async scanner engine, REST API, schema validation |
| CLI | `Typer` & `Rich` | Scriptable headless scanning, target/analytics commands |
| Frontend | Next.js 15 (App Router), React 18, TypeScript, Tailwind CSS | Swiss Technical Grid workstation UI |
| Relational / Queue Schema | PostgreSQL 16+ (SQLAlchemy / Alembic) & Redis 7+ (`docker-compose.yml`) | Persistent DB schema & V3 enterprise queue target |
| Local Workstation Runtime | In-memory `ScanLifecycleRegistry` (bounded at 100 scans) & `TargetRegistry` | Zero-dependency single-workstation execution when DB offline |

---

## 3. Data Model Summary

PostgreSQL schema models (`backend/app/models/` and `infrastructure/scripts/init_db.sql`) define `organizations`, `users`, `projects`, `targets`, `scope_rules`, `scan_jobs`, `discovered_endpoints`, `findings`, `evidence_records`, and `audit_logs` with UUID v4 primary keys.

In local single-workstation mode (without PostgreSQL/Redis active), runtime state is managed via:
- `ScanLifecycleRegistry`: evicts oldest terminal scans when exceeding `100` retained jobs while preserving active `RUNNING` scans.
- `TargetRegistry`: thread-safe target inventory exposed at `/api/v1/targets/` and shared with `active.py` ownership verification and CLI `ashlynx targets`.

---

## 4. Architecture Decision Records (Summary)

- **ADR-001 (ScopeGate IP Pinning):** Resolve DNS immediately prior to socket connect, block prohibited CIDRs across all returned `addrinfo` records, and pin sockets to verified IPs to eliminate TOCTOU DNS rebinding.
- **ADR-002 (Two-Phase Verification):** Keep initial anomalies `SUSPECTED`; require deterministic secondary mathematical invariant / DOM execution / OOB probes before assigning `VERIFIED`.
- **ADR-003 (Monorepo Shared Contracts):** Canonical Pydantic v2 schemas (`shared/schemas/`) mirrored to TypeScript types (`shared/types/`) across backend, CLI, and frontend.
- **ADR-004 (Redaction & SHA-256 Seals):** Scrub credentials in memory via `EvidenceRedactor` and digest request/response pairs using SHA-256 prior to persistence or export.
- **ADR-005 / ADR-006 / ADR-007 (AVIVE Intelligence):** Non-destructive correlation (`DUPLICATE`/`RELATED`/`POTENTIALLY_CORRELATED`), multi-factor explainable confidence (`LOW`/`MEDIUM`/`HIGH`), finite-state validation transitions, and contextual priority computed independently of CVSS.
- **ADR-008 (Modular Coverage Expansion):** Single-purpose passive/active analyzers integrated through `PassiveAnalysisEngine` and `ActivePluginRegistry` with confidence dampening on low-probe anomalies.
- **ADR-009 (SARIF 2.1.0, Target Registry & Bounded Memory):** Standard `application/sarif+json` reporting for CI/CD, server-backed `/api/v1/targets` inventory, and bounded `ScanLifecycleRegistry` retention.
