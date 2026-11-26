# AGENTS.md — Ashlynx WebSec Scanner Developer & AI Agent Directive

## 1. MISSION & AUTHORITATIVE SPECIFICATION
All development, architecture decisions, refactoring, and code contributions on Ashlynx WebSec Scanner must strictly align with the approved **Master Product Requirements Document (`PRD.md`)**.

- **PRD Authority:** `PRD.md` is the authoritative single source of truth. Never contradict `PRD.md`.
- **Release Horizon:** Strictly adhere to the phased capability gates:
  - **MVP:** Core Project/Target isolation, ScopeGate Anti-SSRF socket pinning, Async HTTP Crawler & JS AST Parser, Active OWASP Injection/Misconfig plugins, Two-Phase Deterministic Verification, Typer+Rich CLI, PDF/Markdown/SARIF/JSON reporting, FastAPI API gateway.
  - **V1:** Playwright headless DOM crawling, Form-based authenticated session replay, OpenAPI/GraphQL fuzzing, Automated targeted retesting.
  - **V2:** AI-assisted remediation heuristics, sandboxed community plugins, WebSocket testing.
  - **V3:** Distributed Kubernetes workers, Enterprise PostgreSQL RLS multi-tenancy, Jira/DefectDojo bidirectional sync.

---

## 2. NON-NEGOTIABLE ARCHITECTURAL & SECURITY INVARIANTS

### 2.1 Scanner Self-Defense & Scope Enforcement (Non-Bypassable)
- **Anti-SSRF Socket Pinning:** All outbound scanner traffic must pass through `ScopeGate`. Target hostnames must be resolved to IP addresses immediately prior to socket opening and validated against prohibited CIDRs:
  - RFC 1918 Private Ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
  - Loopback (`127.0.0.0/8`)
  - Cloud Metadata (`169.254.169.254`, IPv6 Link-Local / `fe80::/10`)
  - Broadcast and Multicast
- **Socket IP Pinning:** The validated IP address must be pinned at the socket level to prevent Time-of-Check to Time-of-Use (TOCTOU) DNS rebinding attacks.
- **Zero Scope Escape:** Any URL outside the explicitly configured scope rules must be discarded before active fuzzing payloads are transmitted.

### 2.2 Two-Phase Verification Requirement
- Never classify an active anomaly as `VERIFIED` based merely on reflection or status code shift.
- A finding remains `SUSPECTED` until an independent, deterministic secondary probe proves vulnerability execution:
  - **SQLi:** Randomized mathematical invariant probes (e.g. `AND 8943=8943` vs `AND 8943=8944`).
  - **XSS:** Randomized alphanumeric canary executing unescaped in an executable DOM or script sink.
  - **SSTI:** Dynamic mathematical evaluation (`${{7*191}}` evaluating to `1337`).
  - **SSRF:** Out-of-band listener token callback receipt.
- Unverified anomalies must be clearly designated as `SUSPECTED / UNVERIFIED`.

### 2.3 Safe Scanning & DoS Prevention
- Destructive payloads (e.g., `DROP TABLE`, state deletion, system shutdown) are strictly prohibited.
- Dynamic rate limiting with exponential backoff on HTTP 429 / connection throttle must be honored.

### 2.4 Evidence Integrity & Privacy
- **Chain of Custody:** Every captured HTTP request/response pair must be cryptographically hashed using **SHA-256**.
- **PII & Credential Redaction:** Passwords, Authorization headers (`Bearer [REDACTED]`), session cookies (`session=[REDACTED]`), and sensitive tokens must be masked in memory before persistence to PostgreSQL or logs.

---

## 3. AGENT OPERATIONAL RULES & DEFINITION OF DONE (DoD)

When working on any module in this repository:
1. **Read `PRD.md` first:** Check requirements, CWE mappings, and acceptance criteria before writing code.
2. **Preserve Documentation:** Do not delete, overwrite, or contradict existing architecture documents.
3. **Write Tests:** Every new module, schema, parser, or security check must include unit and integration tests. Line coverage target is $\ge 85\%$.
4. **No External Attack Traffic:** Never fire active scans against unauthorized external targets during development or automated tests. Use containerized local fixtures (DVWA, Juice Shop mocks) and synthetic unit tests.
5. **Architectural Decision Records (ADRs):** Any new technology, protocol, or design choice must be documented in `docs/ARCHITECTURE.md` (ADRs section).
6. **Linting and Typing:** Mandatory type annotations (Python `mypy` / TypeScript `strict: true`). Ensure zero syntax errors and clean linting before committing.
