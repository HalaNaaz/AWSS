# Repository Structure & Module Blueprint

**Document Identifier:** STRUC-WSS-2026-V1.0  
**Parent Specification:** Master PRD (`PRD-WSS-2026-V2.0-FINAL`)

---

## 1. Monorepo Organization Overview

```
ashlynx-websec-scanner/
├── .github/
│   └── workflows/
│       └── ci.yml               # Automated CI quality and security checks
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   └── v1/
│   │   │       ├── endpoints/   # Health, Scans, Findings API routers
│   │   │       └── api.py       # API v1 router aggregator
│   │   ├── audit/               # Immutable audit logging subsystem
│   │   ├── core/                # Configuration, logging, exception hierarchy
│   │   ├── db/                  # SQLAlchemy async session & declarative base
│   │   ├── middleware/          # Security headers & correlation ID middleware
│   │   ├── models/              # Relational database ORM entities
│   │   ├── plugins/             # Extensible vulnerability plugins
│   │   ├── reporting/           # PDF, HTML, Markdown, SARIF export generators
│   │   ├── risk/                # CVSS 4.0 and risk calculation engine
│   │   ├── scanner/
│   │   │   ├── crawler/         # Async HTTP crawler & JS AST parser
│   │   │   ├── evidence/        # Evidence redactor & SHA-256 seal generator
│   │   │   ├── fingerprinting/  # Technology & banner analysis
│   │   │   ├── headers/         # Security header auditor
│   │   │   ├── orchestrator/    # Scan state machine & worker dispatch
│   │   │   ├── reconnaissance/  # Metadata, robots.txt & sitemap ingestion
│   │   │   ├── scope/           # ScopeGate Anti-SSRF socket pinning
│   │   │   ├── tls/             # TLS/SSL baseline configuration auditor
│   │   │   ├── verification/    # Two-Phase deterministic verification engine
│   │   │   └── vulnerabilities/ # Active injection detection modules
│   │   ├── schemas/             # Backend-specific validation schemas
│   │   └── main.py              # FastAPI application entry point
│   ├── tests/
│   │   ├── fixtures/            # Testbed fixtures and mock payloads
│   │   ├── integration/         # Integration test suite
│   │   ├── unit/                # Unit tests for ScopeGate, Health, Redactor
│   │   └── conftest.py          # Pytest fixtures and async test client
│   ├── pyproject.toml           # Backend packaging & tool configurations
│   ├── pytest.ini               # Pytest runtime configuration
│   └── requirements.txt         # Pinned backend dependencies
├── cli/
│   ├── ashlynx/
│   │   ├── commands/            # CLI subcommands (scan, report)
│   │   ├── config/              # CLI runtime settings
│   │   ├── output/              # Rich color-coded terminal formatters
│   │   ├── services/            # Client HTTP adapters
│   │   └── main.py              # Typer CLI application entry point
│   ├── tests/                   # CLI unit and command tests
│   ├── pyproject.toml           # CLI packaging manifest
│   └── requirements.txt         # CLI dependencies
├── frontend/
│   ├── app/
│   │   ├── globals.css          # Tailwind CSS definitions
│   │   ├── layout.tsx           # Dashboard root layout & navigation
│   │   ├── page.tsx             # Security Overview Dashboard
│   │   ├── error.tsx            # Global error boundary
│   │   └── not-found.tsx        # 404 page
│   ├── components/ui/           # Reusable UI component library
│   ├── features/                # Feature-specific components
│   ├── hooks/                   # Custom React hooks
│   ├── lib/                     # Client utilities
│   ├── public/                  # Static assets & brand icons
│   ├── services/                # API client connection layer
│   ├── styles/                  # Additional stylesheets
│   ├── types/                   # Frontend TypeScript interfaces
│   ├── next.config.mjs          # Next.js configuration
│   ├── package.json             # NPM package manifest
│   ├── postcss.config.mjs       # PostCSS configuration
│   ├── tailwind.config.ts       # Tailwind CSS configuration
│   └── tsconfig.json            # TypeScript configuration
├── shared/
│   ├── contracts/               # Shared API contract specifications
│   ├── schemas/                 # Shared Pydantic data schemas
│   └── types/                   # Shared TypeScript models (mirrored)
├── infrastructure/
│   ├── deployment/              # Kubernetes manifests & deployment templates
│   ├── docker/                  # Dockerfiles (backend, frontend, cli)
│   └── scripts/                 # Database initialization & maintenance scripts
├── docs/
│   ├── architecture/            # Architecture specifications & ADRs
│   ├── security/                # Threat models & security policies
│   ├── api/                     # REST API reference documentation
│   ├── database/                # Schema DDL & entity documentation
│   ├── testing/                 # Quality assurance & benchmarking plans
│   └── development/             # Local setup & developer guides
├── .env.example                 # Environment configuration template
├── .gitignore                   # Git ignore patterns
├── AGENTS.md                    # Coding directives for AI agents
├── docker-compose.yml           # Local multi-service development compose
├── PRD.md                       # Authoritative Master PRD (Read-Only)
└── README.md                    # Project overview & quickstart
```
