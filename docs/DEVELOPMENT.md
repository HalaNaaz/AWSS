# Development & Testing Guide

## 1. Prerequisites
- Python `3.11+` (tested through Python `3.14`)
- Node.js `20+` and `npm`
- Optional: Docker & Docker Compose v2 for local PostgreSQL 16 + Redis 7 services

---

## 2. Environment Setup

```bash
# 1. Configure backend environment template
cp .env.example .env

# 2. Create and activate Python virtual environment
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows PowerShell: .\.venv\Scripts\Activate.ps1

pip install -r backend/requirements.txt

# 3. Install frontend dependencies
cd frontend
cp .env.example .env.local
npm install
cd ..
```

### Optional Local PostgreSQL & Redis
```bash
docker compose up -d postgres redis
```

---

## 3. Running Services Locally

### Backend API (`127.0.0.1:8000`)
```bash
export PYTHONPATH=$PWD          # PowerShell: $env:PYTHONPATH = '.'
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

### Frontend Workstation UI (`localhost:3000`)
```bash
cd frontend
npm run build && npm run start  # or: npm run dev
```

### Headless CLI
```bash
export PYTHONPATH=$PWD
python -m cli.ashlynx.main --help
python -m cli.ashlynx.main targets list
python -m cli.ashlynx.main scan https://example.com --authorized --profile SAFE_ACTIVE --format sarif -o scan.sarif
```

---

## 4. Verification & Test Suites

- **Backend & CLI Unit/Integration Tests** (`ALLOW_PRIVATE_IPS=false` enforces strict SSRF protections):
  ```bash
  PYTHONPATH=. ALLOW_PRIVATE_IPS=false pytest backend/tests cli/tests -v
  ```
- **Operational Validation** (runs against the local controlled test target on `127.0.0.1:8089`):
  ```bash
  PYTHONPATH=. ALLOW_PRIVATE_IPS=true pytest tests/operational -v
  ```
- **Frontend Lint, Build & Security Audit:**
  ```bash
  cd frontend
  npm run lint
  npm run build
  npm audit --audit-level=high
  ```
- **Chrome Playwright End-to-End QA:**
  Start the controlled target (`python tests/fixtures/controlled_target_app.py 8089` with `ALLOW_PRIVATE_IPS=true`), backend API (`8000`), and frontend (`3000`), then run:
  ```bash
  PYTHONPATH=. python tests/e2e/test_browser_validation.py
  ```

---

## 5. Coding Conventions
- Keep type annotations complete (`mypy` / TypeScript strict mode) and preserve all `AGENTS.md` security invariants.
- Never run active scans against external domains without explicit written authorization.
- Never commit `.env`, `.env.local`, local paths, or unredacted scan output.
