# Development & Engineering Guide

**Document Identifier:** DEV-WSS-2026-V1.0  
**Parent Specification:** Master PRD (`PRD-WSS-2026-V2.0-FINAL`)

---

## 1. Local Development Principles
Ashlynx WebSec Scanner follows strict software engineering practices:
- Type annotations across 100% of codebase.
- No commit without passing unit tests.
- Zero hardcoded credentials or API keys.
- Comprehensive docstrings for every public class and method.

---

## 2. Directory Layout
- `backend/`: FastAPI application, database ORM models, scanner orchestrator, ScopeGate.
- `cli/`: Typer CLI application for terminal scanning and report export.
- `frontend/`: Next.js 14 web dashboard.
- `shared/`: Pydantic validation models and TypeScript type mirrors.
- `infrastructure/`: Dockerfiles and database initialization scripts.

---

## 3. Daily Development Workflow

### 3.1 Backend Execution
```bash
# In project root
export PYTHONPATH=$PWD
uvicorn backend.app.main:app --reload --port 8000
```
Open interactive Swagger API documentation at: `http://localhost:8000/api/v1/docs`

### 3.2 Running Unit Tests
```bash
pytest backend/tests/unit/ -v --cov=backend/app
```

### 3.3 Running the CLI Locally
```bash
python -m cli.ashlynx.main version
python -m cli.ashlynx.main scan https://example.com --profile QUICK_ASSESSMENT
```

### 3.4 Frontend Execution
```bash
cd frontend
npm install
npm run dev
```
Dashboard available at `http://localhost:3000`
