# Quality Assurance & Testing Strategy

**Document Identifier:** QA-WSS-2026-V1.0  
**Parent Specification:** Master PRD (`PRD-WSS-2026-V2.0-FINAL`)

---

## 1. Testing Hierarchy & Coverage Gates
Ashlynx WebSec Scanner enforces a multi-layered testing pyramid:

```
                ▲
               / \
              /   \
             / E2E \       Playwright automated browser tests & OWASP Benchmark
            /───────\
           / Integr. \     FastAPI API tests with testcontainers (Postgres + Redis)
          /───────────\
         /  Unit Tests \   Pytest: ScopeGate, Redactor, Schemas, Parsers (≥ 85% cov)
        /───────────────\
```

---

## 2. Testing Categories & Suites

### 2.1 Unit Testing (`backend/tests/unit/`)
- **ScopeGate Anti-SSRF:** Tests private IP blocking (RFC 1918), loopback, and cloud metadata (`169.254.169.254`).
- **Scope Rule Matching:** Tests inclusion and exclusion regex patterns.
- **Evidence Redaction:** Asserts Authorization headers, cookies, passwords, and credit cards are scrubbed.
- **Evidence Sealing:** Validates SHA-256 cryptographic seal generation.
- **Data Schemas:** Validates Pydantic serialization and default values.

### 2.2 Integration Testing (`backend/tests/integration/`)
- API endpoints: `/api/v1/healthz`, `/api/v1/scans`, `/api/v1/findings`.
- Database transaction isolation and rollback verification.

### 2.3 Vulnerability Benchmark Suites (Regression Gates)
- Containerized targets:
  - **OWASP Juice Shop:** Tests modern SPA & REST API vulnerabilities.
  - **DVWA (Damn Vulnerable Web Application):** Tests classic SQLi and XSS injection vectors.
  - **OWASP Benchmark v1.2:** Evaluates false-positive rate (Target: $< 5\%$) and recall (Target: $\ge 85\%$).

---

## 3. Running Test Suites
```bash
# Run all unit tests
pytest backend/tests/unit/ -v

# Run with line coverage reporting
pytest backend/tests/ -v --cov=backend/app --cov-report=term-missing
```
