# Ashlynx WebSec Scanner (AWSS-CORE) — Phase 6 Architecture & Gap Analysis

**Document Version:** 1.0.0  
**Date:** November 25, 2026  
**Author:** Principal Security Architect & Senior Full-Stack Engineer  
**Target Phase:** Phase 6 — Advanced Security Scanning Intelligence  
**Baseline Commit:** `565e5b3` (`master`, post-`/findings` 404 regression fix)

---

## 1. Executive Summary

This document presents the pre-implementation architectural audit and gap analysis for **Phase 6 — Advanced Security Scanning Intelligence**. Building upon Phases 1–5 (Core Foundation, Reconnaissance & Passive Analysis, Active Detection, Attack Surface Discovery, and AVIVE Finding Intelligence), Phase 6 elevates Ashlynx from a pipeline of independent scanners into an adaptive, explainable, coverage-aware, and operationally resilient security assessment platform.

---

## 2. Audit of Existing Capabilities & Architecture

### 2.1 Current Pipeline Inventory
- **Scope & Egress (`backend/app/scanner/scope/scope_gate.py`):** Non-bypassable IP resolution & socket pinning (`PinningTransport`), RFC 1918 / Loopback / Cloud Metadata blocking (`allow_private_ips=False` default).
- **HTTP Transport (`backend/app/scanner/crawler/client.py`):** `AsyncHTTPClient` with manual hop-by-hop redirect validation and 5 MB response cap.
- **Reconnaissance & Passive (`backend/app/scanner/reconnaissance/`, `passive/`):** `AsyncCrawler` + `PassiveAnalysisEngine` (6 analyzers).
- **Active Detection (`backend/app/scanner/active/`):** `ActiveDetectionEngine` + `ActivePluginRegistry` (6 analyzers: SQLi, XSS, Misconfig, SSRF, XXE, Auth) governed by `RequestBudgetTracker`.
- **Attack Surface Discovery (`backend/app/scanner/discovery/`):** `AttackSurfaceIntelligenceEngine` (Endpoints, JS AST, Parameter classification, APIs, Assets, Tech Fingerprinting, Graph, Exploration Prioritizer).
- **AVIVE Intelligence (`backend/app/scanner/intelligence/`):** Normalization, correlation/deduplication, explainable confidence, controlled validation lifecycle, contextual risk scoring, and remediation intelligence.
- **Interfaces:** FastAPI (`/api/v1/*`), Typer+Rich CLI (`ashlynx`), Next.js 14 Dashboard (`/`, `/attack-surface`, `/scans`, `/targets`, `/findings`, `/reports`).

---

## 3. Identified Architectural Gaps & Bottlenecks

Direct code inspection identified the following concrete gaps:

1. **Blind Active Target Selection (No Scan Planning):** `ScanOrchestrator.run()` converts every `discovered_endpoints` entry into an `ActiveTarget` and schedules every profile-enabled analyzer against every target regardless of whether the endpoint has parameters, accepts XML/JSON, is static CSS/image, or already exhibits passive findings. This wastes `request_budget` and produces avoidable noise.
2. **Lack of Context-Aware Assessment Suggestions:** Phase 4 parameter categories (`REDIRECT`, `AUTH`, `IDENTIFIER`, `SEARCH`, `FILE`), technology observations (`Express`, `FastAPI`, `Nginx`), and Phase 5 evidence quality/risk context are not fed forward to guide which safe checks should run or what follow-up analyst checks are warranted.
3. **No Security Coverage Intelligence:** Scans report findings, but never report *what was tested vs. skipped vs. untested* mapped to **OWASP Top 10:2021** (`A01`–`A10`), nor *why* checks were skipped (e.g., `PASSIVE_ONLY` profile, zero XML endpoints, budget exhaustion).
4. **Execution Reliability & Retry Gaps (`client.py` & `scan_orchestrator.py`):**
   - `AsyncHTTPClient` lacks configurable bounded retry with exponential backoff on transient `429`/`502`/`503`/`504`/timeout responses, and `SafeValidationWorkflow.run_safe_revalidation` referenced `max_retries=1` which `AsyncHTTPClient.__init__` did not accept.
   - `ScanLifecycleRegistry` lacks duplicate-active-job protection for identical `(target_url, profile)` submissions and lacks stage-level observability telemetry (timings, timeouts, retries, skipped checks).
5. **Missing Scan-Level Analytics & Scan Comparison:** While individual scans output `SeveritySummarySchema` and `ScanIntelligenceSummarySchema`, there is no cross-scan trend engine, vulnerability distribution analytics, technology-to-risk pattern aggregation, or baseline-vs-current scan diffing (`new`, `resolved`, `persisting` findings).
6. **Evidence Lifecycle & Source Provenance Tracking:** Evidence pairs carry `sha256_hash` and `probe_type`, but lack aggregated scan-level evidence quality telemetry, reproducibility tiers, source provenance summaries, and contradictory-signal tracking.

---

## 4. Phase 6 Architecture Design

Phase 6 introduces a cohesive `backend/app/scanner/phase6/` (or `backend/app/scanner/planning/` + `analytics/` + `coverage/`) subsystem integrated directly into `ScanOrchestrator`, `ScanLifecycleRegistry`, `AsyncHTTPClient`, REST APIs, CLI, Reports, and the Next.js UI.

### 4.1 Module Architecture & Responsibilities

| Sub-Phase | Module | Responsibility |
| :--- | :--- | :--- |
| **Contracts** | `shared/schemas/intelligence_v2.py` (or `phase6.py`), `shared/types/models.ts` | Canonical schemas for `ScanPlanSchema`, `ContextAssessmentSchema`, `SecurityCoverageReportSchema`, `ExecutionReliabilityMetricsSchema`, `EvidenceIntelligenceSummarySchema`, `ScanAnalyticsSchema`, `ScanComparisonSchema`. |
| **6B Scan Planner** | `backend/app/scanner/intelligence/planner.py` | Inspects Phase 4 endpoints, parameters, APIs, technologies, and profile limits; generates an explainable `ScanPlanSchema` selecting relevant non-destructive checks, prioritizing high-value targets, pruning redundant/static targets, and strictly preserving `ScopeGate` and `request_budget`. |
| **6C Context-Aware Assessment** | `backend/app/scanner/intelligence/context_assessor.py` | Evaluates endpoint metadata, parameter semantics, tech stack, auth context, existing findings, and confidence/risk to produce targeted `ContextAssessmentSuggestion` items and safe check priorities. |
| **6D Coverage Intelligence** | `backend/app/scanner/intelligence/coverage.py` | Maps executed, partial, skipped, untested, and inconclusive checks to **OWASP Top 10:2021** (`A01`–`A10`), explaining exact skip reasons and preventing false "100% coverage" claims. |
| **6E Execution Reliability** | `backend/app/scanner/crawler/client.py`, `scan_orchestrator.py` | Adds bounded `max_retries` + exponential backoff on 429/5xx/timeouts in `AsyncHTTPClient`, stage timing & timeout/retry telemetry, and duplicate-active-job conflict prevention in `ScanLifecycleRegistry`. |
| **6F Evidence Intelligence** | `backend/app/scanner/intelligence/evidence_intel.py` | Aggregates evidence source provenance, reproducibility distribution, SHA-256 verification status, redaction audit counts, and contradictory evidence flags across a scan. |
| **6G Security Analytics** | `backend/app/scanner/intelligence/analytics.py` | Computes real data-backed analytics across `scan_registry`: vulnerability distributions, risk & coverage trends, endpoint exposure patterns, tech-risk correlations, lifecycle distributions, and deterministic two-scan diff comparison (`ScanComparisonSchema`). Zero synthetic/fake data. |
| **6H–6I UI, API, CLI, Reports** | `api/v1/endpoints/scans.py`, `analytics.py`, `cli/ashlynx/`, `reporting/`, `frontend/app/analytics/page.tsx` & `scans/page.tsx` | Exposes `/api/v1/scans/{id}/plan`, `/coverage`, `/reliability`, `/evidence-intelligence`, `/api/v1/analytics/overview`, `/api/v1/analytics/compare`; adds `ashlynx analytics` & `ashlynx plan` CLI commands; adds **Intelligence & Analytics** UI dashboard (`/analytics`) and Scan Plan/Coverage views without disrupting existing routes. |

---

## 5. Security Boundaries & Non-Bypassable Invariants

1. **Zero Autonomous Scope Expansion:** `ScanPlanner` only plans over endpoints already validated by `ScopeGate` and within `target_base_url`. It cannot add external hosts or override `ScopeRuleType.EXCLUDE`.
2. **Strict Rate & Budget Respect:** Planned probe allocations never exceed `ScanJobCreate.request_budget` or `SCAN_PROFILE_PRESETS` limits.
3. **Bounded Retries:** `AsyncHTTPClient` retries are capped (`max_retries <= 3`) with exponential backoff and re-invoke `ScopeGate` checks on every retry/redirect.
4. **No Fake Dashboard Metrics:** Analytics endpoints return empty/zero-state structures when no scans exist rather than fabricating trend lines.

