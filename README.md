# Ashlynx WebSec Scanner (AWSS)

[![Security CI](https://github.com/HalaNaaz/AWSS/actions/workflows/ci.yml/badge.svg)](https://github.com/HalaNaaz/AWSS/actions)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python Version](https://img.shields.io/badge/Python-3.11%2B-brightgreen.svg)](https://www.python.org/)
[![Next.js](https://img.shields.io/badge/Next.js-15-black.svg)](https://nextjs.org/)

**Ashlynx WebSec Scanner (AWSS)** is an OWASP-aligned Dynamic Application Security Testing (DAST), attack surface discovery, and vulnerability verification platform built for authorized security engineering workflows.

---

## Key Capabilities

- **Unified Hybrid Platform:** FastAPI REST gateway (`backend/`), Typer/Rich CLI (`cli/`), Next.js 15 App Router workstation UI (`frontend/`), and shared Pydantic v2 / TypeScript contracts (`shared/`).
- **Non-Bypassable Anti-SSRF (`ScopeGate`):** Pre-flight DNS resolution, IPv4-mapped IPv6 unwrapping, socket-level IP pinning to defeat TOCTOU DNS rebinding, and strict CIDR blocking across RFC 1918, loopback, cloud metadata (`169.254.169.254`), CGNAT (`100.64.0.0/10`), benchmarking (`198.18.0.0/15`), and IPv6 documentation blocks.
- **Discovery, Analysis & AVIVE Verification:**
  - Bounded asynchronous HTTP crawler (`robots.txt`, sitemap ingestion, static JS AST route extraction).
  - 9 passive HTTP/DOM security analyzers and 8 non-destructive active analyzers with deterministic Two-Phase Verification and request budgets.
  - Attack surface topology graphing (`/attack-surface`), AVIVE correlation/confidence scoring (`/findings`), OWASP Top 10 coverage & scan comparison analytics (`/analytics`).
- **Evidence Integrity & Standardized Exports:** In-memory PII/token/query-parameter redaction (`EvidenceRedactor`), SHA-256 chain-of-custody seals, and export to **JSON**, **HTML**, **Markdown**, and **OASIS SARIF 2.1.0**.

---

## Quickstart

### 1. Environment & Dependencies
```bash
cp .env.example .env

python -m venv .venv
# Linux/macOS: source .venv/bin/activate | Windows PowerShell: .\.venv\Scripts\Activate.ps1
pip install -r backend/requirements.txt

cd frontend && cp .env.example .env.local && npm install && cd ..
```

### 2. Run Backend & Frontend
```bash
# Terminal 1: FastAPI API Server (loopback default 127.0.0.1:8000)
export PYTHONPATH=$PWD          # PowerShell: $env:PYTHONPATH = '.'
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000

# Terminal 2: Next.js Workstation UI (http://localhost:3000)
cd frontend && npm run build && npm run start
```
Interactive API documentation: `http://127.0.0.1:8000/api/v1/docs`

### 3. Run Headless CLI
```bash
python -m cli.ashlynx.main targets list
python -m cli.ashlynx.main scan https://example.com --authorized --profile SAFE_ACTIVE --format sarif -o report.sarif
```

### 4. Optional Local Postgres & Redis
```bash
docker compose up -d postgres redis
```

---

## Testing & Quality Assurance

```bash
# Backend & CLI test suites (strict ScopeGate mode)
ALLOW_PRIVATE_IPS=false PYTHONPATH=. pytest backend/tests cli/tests -v

# Operational suite against controlled test fixture
ALLOW_PRIVATE_IPS=true PYTHONPATH=. pytest tests/operational -v

# Frontend lint, production build & npm security audit
cd frontend && npm run lint && npm run build && npm audit --audit-level=high
```

---

## Security & Authorized-Use Policy

- **Authorized Systems Only:** CLI scans require `--authorized` (`-a`) and active API probes require `"authorized": true`. Never target external applications without explicit owner permission.
- **Safe Defaults:** Backend binds to `127.0.0.1` (`ENFORCE_LOCAL_BOUNDARY=true`, optional `API_AUTH_TOKEN`), and `ALLOW_PRIVATE_IPS` defaults to `false`.
- **Single-Workstation Constraint:** Without PostgreSQL/Redis persistence active, `ScanLifecycleRegistry` (capped at `100` jobs) and `TargetRegistry` run in process memory and reset on restart.

---

## Repository Structure

```
AWSS/
├── .github/workflows/ci.yml    # Backend/CLI tests, Next.js build/lint/audit & Bandit SAST
├── backend/                    # FastAPI gateway, scanner engines, reporting & unit/integration tests
├── cli/                        # Typer/Rich CLI and CLI unit tests
├── docs/
│   ├── ARCHITECTURE.md         # System architecture, stack summary, DB model & ADRs
│   ├── API.md                  # REST API endpoint reference
│   ├── DEVELOPMENT.md          # Setup, local workflows & test commands
│   └── SECURITY.md             # ScopeGate anti-SSRF, two-phase safety, redaction & threat controls
├── frontend/                   # Next.js 15 App Router UI
├── infrastructure/             # Dockerfiles, Kubernetes manifests & DB init scripts
├── shared/                     # Shared Pydantic v2 schemas, contracts & TypeScript types
├── tests/                      # Operational validation, Chrome E2E suite & controlled fixtures
├── .env.example                # Safe configuration template
├── AGENTS.md                   # Engineering & security invariants
├── PRD.md                      # Master Product Requirements Document
├── docker-compose.yml          # Local Postgres & Redis service compose
├── pytest.ini                  # Pytest runtime & asyncio configuration
└── README.md
```

---

## Documentation
- [Architecture & ADRs](docs/ARCHITECTURE.md)
- [REST API Reference](docs/API.md)
- [Development & Testing Guide](docs/DEVELOPMENT.md)
- [Security Architecture & Policy](docs/SECURITY.md)
- [Master Product Requirements Document](PRD.md)
- [Agent & Developer Invariants](AGENTS.md)
