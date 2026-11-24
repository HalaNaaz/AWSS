# Architecture Decision Records (ADR)
## Ashlynx WebSec Scanner

---

### ADR-001: Implementation of ScopeGate Socket IP Pinning for Anti-SSRF
* **Status:** Approved
* **Context:** DAST scanners are frequently targeted by SSRF and DNS rebinding attacks to probe internal networks or cloud metadata endpoints (`169.254.169.254`).
* **Decision:** Outbound scanner connections must pass through `ScopeGate`. Target hostnames are resolved immediately prior to socket creation, validated against prohibited CIDRs (RFC 1918, RFC 3927, Loopback), and the socket is pinned to the validated IP address.
* **Consequences:** Eliminates TOCTOU DNS rebinding attacks and prevents internal network pivoting.

---

### ADR-002: Two-Phase Vulnerability Verification
* **Status:** Approved
* **Context:** High false-positive rates degrade developer trust and burden security teams with triage overhead.
* **Decision:** Active scanning is split into Phase 1 (Heuristic Anomaly Detection) and Phase 2 (Deterministic Verification). No finding is classified as `VERIFIED` without passing an independent, secondary mathematical invariant probe or out-of-band listener token callback.
* **Consequences:** Unverified anomalies remain labeled as `SUSPECTED / UNVERIFIED`. Benchmark false-positive rate targeted at $< 5\%$.

---

### ADR-003: Monorepo Architecture with Shared Contracts
* **Status:** Approved
* **Context:** The platform requires parity between the interactive Web Dashboard and the headless CLI while avoiding duplicated data schemas.
* **Decision:** A monorepo structure containing `backend/`, `frontend/`, `cli/`, `shared/`, `infrastructure/`, and `docs/`. Pydantic models in `shared/schemas/` define canonical entities, with mirrored TypeScript definitions in `shared/types/`.
* **Consequences:** Ensures consistency across API responses, CLI tables, and frontend UI components.

---

### ADR-004: In-Memory Redaction & SHA-256 Chain of Custody
* **Status:** Approved
* **Context:** Evidence collected during scans may contain customer credentials or sensitive tokens, yet forensic admissibility requires tamper-evident integrity.
* **Decision:** Evidence strings are redacted in memory before database persistence (masking Authorization headers, cookies, and passwords). Every request/response pair is sealed with a cryptographic SHA-256 hash.
* **Consequences:** Complies with privacy invariants (zero plaintext credentials in database) while maintaining audit integrity.
