# Environment Setup & Prerequisites

**Document Identifier:** SETUP-WSS-2026-V1.0  
**Parent Specification:** Master PRD (`PRD-WSS-2026-V2.0-FINAL`)

---

## 1. System Requirements

### 1.1 Development Tools
- **Python:** Version 3.11 or higher (Python 3.14 compatible).
- **Node.js:** Version 20.x or 24.x LTS.
- **Git:** Version 2.40+.
- **Docker & Docker Compose:** Docker Engine 24+ with Compose v2.

---

## 2. Step-by-Step Setup

### Step 1: Environment Variables
Copy the template configuration:
```bash
cp .env.example .env
```
Ensure `DATABASE_URL` and `SECRET_KEY` are appropriately configured.

### Step 2: Python Virtual Environment
```bash
python -m venv .venv

# On Linux/macOS
source .venv/bin/activate

# On Windows (PowerShell)
.venv\Scripts\Activate.ps1

pip install -r backend/requirements.txt
pip install -r cli/requirements.txt
```

### Step 3: Launch Local Services via Docker Compose
```bash
docker compose up -d postgres redis
```
This starts:
- PostgreSQL 16 on port `5432` with database `ashlynx_websec`.
- Redis 7 on port `6379`.

### Step 4: Run Database Migrations / Schema Bootstrap
```bash
# Verify database connection
python -c "import socket; s = socket.socket(); s.connect(('localhost', 5432)); print('Postgres reachable'); s.close()"
```

### Step 5: Start Backend API Server
```bash
export PYTHONPATH=$PWD
uvicorn backend.app.main:app --reload --port 8000
```
Verify health:
```bash
curl http://localhost:8000/api/v1/healthz
```

### Step 6: Start Web Dashboard
```bash
cd frontend
npm install
npm run dev
```
Access at `http://localhost:3000`.
