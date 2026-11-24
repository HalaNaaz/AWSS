# Ashlynx WebSec Scanner

[![Security CI](https://github.com/AshlynxCyber/ashlynx-websec-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/AshlynxCyber/ashlynx-websec-scanner/actions)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python Version](https://img.shields.io/badge/Python-3.11%2B-brightgreen.svg)](https://www.python.org/)
[![Next.js](https://img.shields.io/badge/Next.js-14-black.svg)](https://nextjs.org/)

**Ashlynx WebSec Scanner** is an enterprise-grade, hybrid web application security assessment, DAST, and automated vulnerability scanning platform engineered by [AshlynxCyber](https://www.ashlynxcyber.in/).

---

## Key Capabilities

- **Hybrid Interfaces:** Unified engine accessible via interactive **Next.js Web Dashboard** and headless **Typer CLI**.
- **ScopeGate Defense:** Socket-level DNS pinning and anti-SSRF protection blocking RFC 1918 and cloud metadata (`169.254.169.254`).
- **Two-Phase Verification:** Deterministic mathematical invariant testing separating suspected anomalies from verified flaws ($< 5\%$ false-positive target).
- **Cryptographic Chain of Custody:** In-memory PII/credential redaction and SHA-256 integrity sealing on all raw HTTP evidence.
- **Standardized Reporting:** On-demand export to Executive PDF, Technical Markdown, SARIF v2.1.0, and structured JSON.

---

## Quickstart

### Prerequisites
- Python 3.11+
- Node.js 20+
- Docker & Docker Compose

### 1. Launch Backend & Supporting Services
```bash
# Clone and enter workspace
cp .env.example .env

# Launch PostgreSQL and Redis
docker compose up -d postgres redis

# Run backend API
export PYTHONPATH=$PWD
python -m uvicorn backend.app.main:app --reload --port 8000
```
API Documentation: `http://localhost:8000/api/v1/docs`

### 2. Run Headless CLI
```bash
python -m cli.ashlynx.main version
python -m cli.ashlynx.main scan https://example.com --profile QUICK_ASSESSMENT
```

### 3. Start Web Dashboard
```bash
cd frontend
npm install
npm run dev
```
Dashboard: `http://localhost:3000`

---

## Testing & Quality Assurance
```bash
# Run unit test suite
pytest backend/tests/unit -v --cov=backend/app
```

---

## Architecture & Documentation
Comprehensive specifications are available in the [`docs/`](docs/) directory:
- [Software Architecture](docs/architecture/SOFTWARE_ARCHITECTURE.md)
- [Repository Structure](docs/architecture/REPOSITORY_STRUCTURE.md)
- [Technology Stack](docs/architecture/TECHNOLOGY_STACK.md)
- [Database Design](docs/database/DATABASE_DESIGN.md)
- [API Specification](docs/api/API_SPECIFICATION.md)
- [Security Architecture](docs/security/SECURITY_ARCHITECTURE.md)
- [Threat Model (STRIDE)](docs/security/THREAT_MODEL.md)
- [Architecture Decision Records (ADRs)](docs/architecture/ARCHITECTURE_DECISION_RECORDS.md)
- [Developer Directives & Agent Rules](AGENTS.md)

---
*AshlynxCyber Security Systems — Internal & Confidential*
