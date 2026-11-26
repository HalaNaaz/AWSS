# Repository Structure & Module Blueprint

**Document Identifier:** STRUC-WSS-2026-V1.0  
**Parent Specification:** Master PRD (`PRD-WSS-2026-V2.0-FINAL`)

---

## 1. Monorepo Organization Overview

```
AWSS/
├── .github/
│   └── workflows/
│       └── ci.yml               # GitHub Actions backend/CLI/frontend CI & Bandit SAST
├── backend/
│   ├── alembic/                 # Database migration configuration & scripts
│   ├── app/
│   │   ├── api/v1/
│   │   │   ├── endpoints/       # health, targets, scans, findings, recon, passive, active, discovery, analytics, reports
│   │   │   └── api.py           # API v1 router aggregator
│   │   ├── core/                # Configuration, logging, exception hierarchy
│   │   ├── db/                  # SQLAlchemy async session & declarative base
│   │   ├── middleware/          # Security headers, correlation ID, local boundary & token auth
│   │   ├── models/              # Relational database ORM entities
│   │   ├── reporting/           # JSON, HTML, Markdown, and SARIF 2.1.0 generators
│   │   └── scanner/
│   │       ├── active/          # ActiveDetectionEngine, Safe Active Analyzers & Registry
│   │       ├── passive/         # PassiveAnalysisEngine (headers, cookies, CORS, cache, auth, DOM)
│   │       ├── crawler/         # Hardened AsyncHTTPClient (pinning), normalizer, robots/sitemap
│   │       ├── discovery/       # AttackSurfaceIntelligenceEngine, JS AST analyzer, topology graph
│   │       ├── evidence/        # EvidenceRedactor & SHA-256 chain-of-custody sealer
│   │       ├── intelligence/    # Phase 5 AVIVE & Phase 6 Planner / Coverage / Analytics
│   │       ├── orchestration/   # ScanOrchestrator & bounded ScanLifecycleRegistry
│   │       ├── reconnaissance/  # ReconOrchestrator
│   │       └── scope/           # ScopeGate Anti-SSRF socket pinning
│   ├── tests/                   # Unit & integration test suites
│   ├── pyproject.toml           # Backend packaging & tool configurations
│   ├── pytest.ini               # Backend pytest configuration
│   └── requirements.txt         # Pinned backend dependencies
├── cli/
│   ├── ashlynx/
│   │   ├── commands/            # scan, recon, attack_surface, targets, findings, analytics, report
│   │   ├── output/              # Rich terminal tables and formatters
│   │   └── main.py              # Typer CLI application entry point
│   └── tests/                   # CLI unit tests
├── frontend/
│   ├── app/                     # Next.js 15 App Router (/, targets, scans, attack-surface, findings, analytics, reports)
│   ├── components/              # AppShell, navigation, Swiss Technical Grid UI primitives
│   ├── services/                # Backend REST API fetch wrapper
│   ├── types/                   # TypeScript domain models
│   ├── next.config.mjs          # Next.js configuration
│   ├── package.json             # NPM package manifest
│   └── tailwind.config.ts       # Tailwind CSS design tokens
├── shared/
│   ├── contracts/               # Shared API contract specifications
│   ├── schemas/                 # Canonical Pydantic v2 schemas
│   └── types/                   # Mirrored TypeScript definitions
├── infrastructure/
│   ├── deployment/              # Deployment manifests & templates
│   ├── docker/                  # Dockerfiles
│   └── scripts/                 # Database & setup scripts
├── tests/
│   ├── e2e/                     # Chrome Playwright end-to-end QA suite
│   ├── fixtures/                # Controlled local test target fixtures
│   └── operational/             # Operational scanner & security validation suite
├── audit_evidence/              # Reproducible audit runners, canonical logs, and UI screenshots
├── docs/
│   ├── api/                     # REST API specification
│   ├── architecture/            # Architecture, ADRs, roadmap, and phase specifications
│   ├── archive/phases/          # Archived Phase 1–7 implementation reports & matrices
│   ├── audit/                   # End-to-end audit reports, findings register, remediation logs
│   ├── database/                # Database schema documentation
│   ├── development/             # Local setup & developer guides
│   ├── releases/                # Release readiness & verification reports
│   ├── security/                # Security architecture & STRIDE threat model
│   └── testing/                 # QA strategy & test matrices
├── .env.example                 # Safe configuration template
├── .gitignore                   # Ignore rules
├── AGENTS.md                    # Developer & AI agent invariants
├── docker-compose.yml           # Local Postgres & Redis service compose
├── PRD.md                       # Authoritative Master Product Requirements Document
├── pytest.ini                   # Root pytest & asyncio loop scope configuration
└── README.md                    # Repository overview, quickstart & policy
```
