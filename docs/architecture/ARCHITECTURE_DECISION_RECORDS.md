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

---

### ADR-005: AVIVE Traceable Correlation & Non-Destructive Primary Selection
* **Status:** Approved
* **Context:** Running passive and active analyzers across multi-route web applications generates overlapping observations (e.g., passive cookie/header flaws across many URLs, or passive + active checks on the same parameter). Silently dropping duplicates destroys forensic evidence.
* **Decision:** The Phase 5 Correlation Engine preserves all original normalized findings and links them via `CorrelationGroup` records distinguishing `DUPLICATE`, `RELATED`, `POTENTIALLY_CORRELATED`, and `INDEPENDENT` relationships. A primary finding is deterministically selected while duplicate records retain `is_duplicate`, `duplicate_of`, and `correlation_group_id` traceability.
* **Consequences:** Analysts get deduplicated primary triage queues without losing underlying module evidence or auditability.

---

### ADR-006: Explainable Confidence Separation & Controlled Validation Lifecycle
* **Status:** Approved
* **Context:** Scalar confidence numbers and conflating severity with confidence lead to false-positive escalation (e.g., treating a speculative HIGH-severity alert as confirmed).
* **Decision:** Confidence is computed transparently from structured evidence quality factors (`detection_method_reliability`, `reproducibility`, `evidence_completeness`, `signal_quality`, `response_consistency`, `contradictory_evidence`, `corroboration`) yielding `LOW`/`MEDIUM`/`HIGH` plus explicit rationales. HIGH/CRITICAL findings with LOW confidence are prevented from auto-validation and flagged `NEEDS_REVIEW`. State transitions follow an audited finite-state machine (`SafeValidationWorkflow`).
* **Consequences:** Prevents false-positive elevation and ensures analyst-auditable validation history.

---

### ADR-007: Contextual Risk Assessment Independent from CVSS
* **Status:** Approved
* **Context:** CVSS measures intrinsic technical vulnerability characteristics, whereas remediation urgency depends on attack surface context (authentication exposure, parameter type, related findings, technology stack, and configured asset criticality).
* **Decision:** `ContextualRiskEngine` calculates an explainable contextual priority (`CRITICAL`..`INFO`, `0–100`) alongside—never overwriting—`cvss_score` and `severity`. Missing contextual inputs such as unconfigured asset criticality are explicitly declared in `data_limitations` rather than fabricated.
* **Consequences:** Preserves standards compliance for CVSS reporting while enabling context-driven prioritization.

---

### ADR-008: Phase 7 Modular Assessment Expansion & Signal Quality Dampening
* **Status:** Approved
* **Context:** Phases 1–6 established passive headers/cookies/CORS/disclosure/HTML checks and active SQLi/XSS/SSRF/XXE/Misconfig/Auth analyzers, leaving targeted gaps in response caching, JWT/token hygiene, client-side DOM/tabnabbing/postMessage security, two-phase path traversal verification, and API security checks.
* **Decision:** Add focused, single-purpose passive analyzers (`SEC-CACHE-ANALYZER`, `AUTH-TOKEN-ANALYZER`, `CLIENT-SEC-ANALYZER`) and bounded non-destructive active analyzers (`ACT-TRAVERSAL-ANALYZER`, `ACT-API-SEC-ANALYZER`) registered in `PassiveAnalysisEngine` and `ActivePluginRegistry`. Strengthen `ConfidenceEngine` signal-quality dampening for low-probe unverified anomalies rather than creating a parallel finding schema.
* **Consequences:** Preserves non-bypassable `ScopeGate` socket pinning, two-phase deterministic verification, and AVIVE compatibility while expanding OWASP Top 10 coverage and reducing unverified noise.

---

### ADR-009: Standard SARIF 2.1.0 Reporting, Target Scope API & Bounded In-Memory Registry
* **Status:** Approved
* **Context:** Security engineering workflows require OASIS SARIF 2.1.0 output for CI code-scanning integration, server-backed target scope inventory (`TargetRegistry`) shared across Web UI and CLI, and memory-bounded retention for long-running local workstation sessions.
* **Decision:**
  1. Register `SARIFReportGenerator` (`ReportFormat.SARIF`, `application/sarif+json; charset=utf-8`) in `ReportManager` mapping severity (`error`/`warning`/`note`), CWE tags, CVSS security-severity scores, endpoint locations, and SHA-256 evidence fingerprints.
  2. Expose REST CRUD endpoints at `/api/v1/targets` (`TargetRegistry`) enforcing URL scheme validation and `ScopeGate` private-IP checks, synchronized with Next.js UI and `ashlynx targets` CLI.
  3. Enforce `DEFAULT_MAX_RETAINED_SCANS = 100` eviction in `ScanLifecycleRegistry` on oldest terminal scans while never evicting active `RUNNING` scans.
* **Consequences:** Enables full CI SARIF adoption, eliminates volatile UI-only target state, and prevents unbounded memory growth in local workstation mode.
