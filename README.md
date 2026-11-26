# Ashlynx WebSec Scanner (AWSS)

[![Security CI](https://github.com/HalaNaaz/AWSS/actions/workflows/ci.yml/badge.svg)](https://github.com/HalaNaaz/AWSS/actions)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python Version](https://img.shields.io/badge/Python-3.11%2B-brightgreen.svg)](https://www.python.org/)
[![Next.js](https://img.shields.io/badge/Next.js-15-black.svg)](https://nextjs.org/)

**Ashlynx WebSec Scanner (AWSS)** is an OWASP-aligned Dynamic Application Security Testing (DAST), attack surface discovery, and vulnerability verification platform built for authorized security engineering workflows.

---

## Architecture & Key Capabilities

- **Monorepo Platform:** FastAPI REST gateway (`backend/`), Typer/Rich CLI (`cli/`), Next.js 15 App Router workstation UI (`frontend/`), and canonical Pydantic v2 / TypeScript contracts (`shared/`).
- **Non-Bypassable Anti-SSRF (`ScopeGate`):** Pre-flight DNS resolution, IPv4-mapped IPv6 unwrapping, socket-level IP pinning to defeat TOCTOU DNS rebinding, and strict blocking of RFC 1918, loopback, cloud metadata (`169.254.169.254`), CGNAT (`100.64.0.0/10`), benchmarking (`198.18.0.0/15`), and IPv6 documentation ranges.
- **Multi-Engine Analysis & Intelligence:**
  - Bounded asynchronous web crawler with `robots.txt` / sitemap ingestion and static JS AST endpoint/route extraction.
  - Passive security analyzers (headers, CSP, cookies, CORS, caching headers, JWT/token exposure, DOM/client risks, error/secret disclosure).
  - Non-destructive active analyzers with deterministic Two-Phase Verification (SQLi, reflected XSS, SSRF, XXE, security misconfigurations, path traversal, auth/session flaws, API security).
  - Attack surface topology graphing, AVIVE finding correlation/confidence scoring, contextual risk ranking, OWASP Top 10 coverage analytics, and baseline-vs-current scan diffs.
- **Forensic Evidence Integrity:** In-memory redaction of `Authorization` headers, session cookies, JSON secrets, `.env` keys, private keys, and sensitive query parameters paired with SHA-256 chain-of-custody seals.
- **Standardized Reporting:** Interactive preview and download in **JSON**, **HTML** (HTML-escaped and sandboxed), **Markdown**, and **OASIS SARIF 2.1.0**.

---

## Supported Workflows

1. **Authorized Target Registration:** Manage target scopes and ScopeGate boundaries via the `/targets` UI, `POST /api/v1/targets/`, or `ashlynx targets` CLI.
2. **Scan Execution & Cancellation:** Launch `PASSIVE_DISCOVERY`, `PASSIVE_ONLY`, `SAFE_ACTIVE`, `STANDARD_ACTIVE`, `QUICK_ASSESSMENT`, `FULL_ASSESSMENT`, `SAFE_MODE`, or `API_TARGETED` assessments via Web Dashboard or CLI, with live polling and cooperative cancellation.
3. **Attack Surface Inspection:** Explore discovered endpoints, classified parameters, REST/GraphQL/WebSocket APIs, client assets, and topology graphs (`/attack-surface`).
4. **AVIVE Triage & Validation:** Filter findings by severity, confidence, validation state, CWE, or contextual priority and track validation transitions (`/findings`).
5. **Analytics & Report Export:** Inspect OWASP coverage, execution reliability, scan comparisons (`/analytics`), and export JSON/HTML/Markdown/SARIF 2.1.0 reports (`/reports`).

---

## Installation & Environment Setup

### Prerequisites
- Python `3.11+`
- Node.js `20+` and `npm`
- Optional: Docker & Docker Compose (for local PostgreSQL 16 + Redis 7 services)

### 1. Environment Configuration
```bash
cp .env.example .env
```
Key configuration variables in [`.env.example`](.env.example):
- `HOST=127.0.0.1`, `PORT=8000` — Loopback-only default bind for single-workstation safety.
- `ENFORCE_LOCAL_BOUNDARY=true` — Rejects non-loopback or proxied remote requests (`HTTP 403`) unless authenticated.
- `API_AUTH_TOKEN` — Optional static Bearer / `X-API-Key` token required on `/api/v1/*` whenever configured.
- `ALLOW_PRIVATE_IPS=false` — Must remain `false` outside explicitly authorized local lab fixtures (`127.0.0.1:8089`).

### 2. Backend Setup & Startup
```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate | Windows PowerShell: .\.venv\Scripts\Activate.ps1
pip install -r backend/requirements.txt

export PYTHONPATH=$PWD   # PowerShell: $env:PYTHONPATH = '.'
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```
OpenAPI documentation (development mode): `http://127.0.0.1:8000/api/v1/docs`

### 3. Frontend Workstation Startup
```bash
cd frontend
cp .env.example .env.local
npm install
npm run build
npm run start
```
Dashboard URL: `http://localhost:3000` *(For live development hot-reload, run `npm run dev`.)*

### 4. Headless CLI Usage
```bash
# Display banner and version
python -m cli.ashlynx.main version

# Manage authorized targets
python -m cli.ashlynx.main targets list
python -m cli.ashlynx.main targets add --name "Staging" --url https://staging.example.com

# Run an authorized assessment (--authorized / -a is mandatory)
python -m cli.ashlynx.main scan https://example.com --authorized --profile SAFE_ACTIVE --format sarif -o report.sarif
```

### 5. Docker Compose (PostgreSQL & Redis Infrastructure)
```bash
docker compose up -d postgres redis
```

---

## Testing & Quality Assurance

Run test suites locally with `PYTHONPATH=.`:
```bash
# Backend & CLI unit/integration suite (Strict ScopeGate mode)
ALLOW_PRIVATE_IPS=false pytest backend/tests cli/tests -v

# Operational suite against local controlled target fixture
ALLOW_PRIVATE_IPS=true pytest tests/operational -v

# Frontend lint, production build, and dependency security audit
cd frontend && npm run lint && npm run build && npm audit --audit-level=high
```
When backend (`127.0.0.1:8000`), frontend (`localhost:3000`), and the controlled fixture (`python tests/fixtures/controlled_target_app.py 8089` with `ALLOW_PRIVATE_IPS=true`) are running, execute the Chrome Playwright E2E suite:
```bash
python tests/e2e/test_browser_validation.py
```

---

## Authorized-Use Policy & Security Boundaries

- **Authorized Targets Only:** Do **not** run AWSS against systems without explicit written permission from the system owner. CLI scans require `--authorized` (`-a`) and active API probes require `"authorized": true`.
- **Non-Destructive Probing:** All active checks are strictly bounded (`RequestBudgetTracker`) and prohibit destructive SQL (`DROP`/`DELETE`) or state-corrupting payloads.
- **Development Default Safety:** `ScopeGate` rejects private, loopback, CGNAT, and metadata IPs by default (`ALLOW_PRIVATE_IPS=false`), and the API enforces `127.0.0.1` loopback binding unless hardened behind `API_AUTH_TOKEN`.

---

## Accepted Limitations & Roadmap

- **Single-Workstation In-Memory State (`ARCH-DB-01`):** Without running PostgreSQL/Redis repository wiring enabled, active scan jobs/reports (`ScanLifecycleRegistry`, capped at `100` retained scans) and target registrations (`TargetRegistry`) reside in process memory and reset on backend restart. Do **not** deploy for multi-tenant persistent storage until V3 database persistence and JWT/RBAC are enabled.
- **Roadmap:** Aligns with [`PRD.md`](PRD.md) and [`IMPLEMENTATION_ROADMAP.md`](docs/architecture/IMPLEMENTATION_ROADMAP.md) (`MVP` Workstation Engine -> `V1` Headless Playwright Crawling & OpenAPI/GraphQL Fuzzing -> `V2` Sandboxed Community Plugins & WebSockets -> `V3` Kubernetes Workers, PostgreSQL RLS, Jira/DefectDojo Sync).

---

## Repository Structure

```
AWSS/
├── .github/workflows/ci.yml    # Automated backend/CLI tests, Next.js CI, and Bandit SAST
├── backend/                    # FastAPI gateway, scanner engines, reporting & tests
├── cli/                        # Typer/Rich CLI and CLI unit tests
├── frontend/                   # Next.js 15 App Router UI
├── shared/                     # Shared Pydantic v2 schemas, API contracts & TS types
├── infrastructure/             # Dockerfiles, Kubernetes manifests & DB scripts
├── tests/                      # Operational validation, Chrome E2E suite & controlled fixtures
├── audit_evidence/             # Reproducible audit runners, canonical logs & UI screenshots
├── docs/                       # Canonical architecture, security, API, audit, release & archive docs
├── AGENTS.md                   # Engineering & security invariants
├── PRD.md                      # Master Product Requirements Document
└── README.md                   # Project entry point documentation
```

### Canonical Documentation
- [Documentation Index](docs/README.md)
- [Software Architecture](docs/architecture/SOFTWARE_ARCHITECTURE.md) & [ADRs](docs/architecture/ARCHITECTURE_DECISION_RECORDS.md)
- [Security Architecture](docs/security/SECURITY_ARCHITECTURE.md) & [Threat Model (STRIDE)](docs/security/THREAT_MODEL.md)
- [API Specification](docs/api/API_SPECIFICATION.md) & [Database Design](docs/database/DATABASE_DESIGN.md)
- [Final End-to-End Audit Report](docs/audit/AWSS_CORE_FINAL_END_TO_END_AUDIT_REPORT.md) & [Findings Register](docs/audit/AWSS_CORE_FINDINGS_REGISTER.md)
- [Release Readiness Assessment](docs/releases/AWSS_CORE_RELEASE_READINESS.md)
- [Historical Phase 1–7 Archive](docs/archive/phases/)
