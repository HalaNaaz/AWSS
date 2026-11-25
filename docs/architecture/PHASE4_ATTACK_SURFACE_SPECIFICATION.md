# PHASE 4: ADVANCED ATTACK SURFACE DISCOVERY & INTELLIGENCE SPECIFICATION

**Document Identifier:** SPEC-WSS-2026-PHASE4-V1.0  
**Parent Document:** Master PRD (`PRD-WSS-2026-V2.0-FINAL`)  
**Status:** Approved & Implemented  
**Date:** 2026-11-25  

---

## 1. Architectural Scope & Objectives

Phase 4 of Ashlynx WebSec Scanner transitions the platform from a conventional URL crawler into an interconnected, evidence-grounded attack surface intelligence system. 

It accomplishes:
1. **Multi-Source Endpoint Discovery (Module 4.1):** Consolidating routes across HTML tags, redirects, stylesheets, robots.txt, sitemaps, API specs, and static client scripts.
2. **Static JavaScript Intelligence (Module 4.2):** Lexical parsing and AST pattern matching without executing untrusted scripts (Zero Dynamic Evaluation invariant).
3. **Parameter Intelligence & Classification (Module 4.3):** Heuristic classification into 10 semantic categories with strict privacy-preserving value redaction (`[REDACTED]`).
4. **API Inventory & Surface Categorization (Module 4.4):** Distinguishing REST, GraphQL, OpenAPI/Swagger, JSON APIs, WebSockets, and RPC architectures with version extraction.
5. **Bounded Asset Catalog (Module 4.5):** Cataloging client-side assets (JS, CSS, images, fonts, documents, source maps) with MIME tracking and memory limits.
6. **Multi-Signal Technology Fingerprinting (Module 4.6):** Correlating indicators to distinguish confirmed versioned signatures from inferred guesses.
7. **In-Memory Attack Surface Graph (Module 4.7):** Interconnecting domains, endpoints, parameters, forms, assets, technologies, and findings with cycle prevention and Cytoscape/JSON export without external graph DB dependencies.
8. **Evidence-Based Exploration Prioritization (Module 4.8):** Heuristic exploration scoring ($0 - 100$) guiding pentester focus, distinctly separated from CVSS vulnerability severity.

---

## 2. Invariant & Security Guardrails

### 2.1 ScopeGate Egress Enforcement
All candidate URLs discovered through HTML, JavaScript, redirects, or sitemaps must pass through `ScopeGate.validate_url_in_scope()`. Any URL pointing to private RFC 1918 ranges, loopback addresses, or cloud metadata services (`169.254.169.254`) is rejected immediately prior to socket allocation.

### 2.2 Zero Dynamic JavaScript Execution
Untrusted JavaScript bundles retrieved during crawling are evaluated strictly via static token and regular expression analysis. Dynamic execution engines (`eval`, Node.js VM, V8 sandboxes) are prohibited to prevent remote code execution or sandbox escapes on malicious target payloads.

### 2.3 Safe GraphQL & API Probing
API discovery inspects endpoints passively or via standard documentation routes (`/openapi.json`, `/swagger.json`, `/graphql`). Deep mutation fuzzing or unauthorized schema dictionary brute-forcing is strictly avoided.

### 2.4 Privacy & Sensitive Parameter Redaction
All parameter intelligence instances for `AUTH`, `SESSION`, and `SENSITIVE` categories enforce sample value redaction (`[REDACTED]`) before persistence in memory, JSON serialization, database models, or logs.

---

## 3. Subsystem Architecture

```mermaid
flowchart TD
    Target[Target URL / Base Scope] --> ScopeGate[ScopeGate Socket Pinning]
    ScopeGate --> Crawler[Async Bounded Crawler]

    Crawler --> EndpointEngine[Advanced Endpoint Discovery (4.1)]
    Crawler --> JSAnalyzer[JS Static Intelligence (4.2)]
    Crawler --> ParamEngine[Parameter Intelligence (4.3)]
    Crawler --> APIEngine[API Discovery & Inventory (4.4)]
    Crawler --> AssetEngine[Bounded Asset Catalog (4.5)]
    Crawler --> TechEngine[Multi-Signal Tech Fingerprinter (4.6)]

    EndpointEngine --> MasterEngine[AttackSurfaceIntelligenceEngine]
    JSAnalyzer --> MasterEngine
    ParamEngine --> MasterEngine
    APIEngine --> MasterEngine
    AssetEngine --> MasterEngine
    TechEngine --> MasterEngine

    MasterEngine --> Graph[Attack Surface Graph (4.7)]
    MasterEngine --> Prioritizer[Exploration Prioritization (4.8)]

    Graph --> REST_API[/api/v1/discovery/*]
    Prioritizer --> REST_API
    REST_API --> UI[Next.js Attack Surface Dashboard]
    REST_API --> CLI[ashlynx attack-surface]
```

---

## 4. Prioritization Scoring Formula

Exploration Priority Score ($S$) is computed additively in the interval $[0.0, 100.0]$:
$$S = \min\left(100.0, \sum w_i\right)$$

Where observable signals contribute:
- **Authentication / Sensitive Route:** $+25$
- **File Handling / Upload Capability:** $+20$
- **Redirect / URL Parameter (Open Redirect / SSRF Risk):** $+15$
- **High-Risk Injection Parameter (Identifier / Search):** $+15$
- **State-Mutating Form / POST Target:** $+10$
- **Structured Dynamic API Path:** $+10$
- **Associated Security Findings Present:** $+\min(25, 10 \times N)$
- **HTTP Status Code Anomaly ($\ge 400$):** $+5$

Priority bands:
- `HIGH`: $S \ge 60.0$
- `MEDIUM`: $30.0 \le S < 60.0$
- `LOW`: $S < 30.0$
