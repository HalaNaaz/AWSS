# Threat Model (STRIDE) & Risk Register

**Document Identifier:** TM-WSS-2026-V1.0  
**Parent Specification:** Master PRD (`PRD-WSS-2026-V2.0-FINAL`)

---

## 1. Threat Modeling Overview
Using the Microsoft STRIDE methodology, we systematically evaluate threat actors, attack surfaces, and mitigations for the Ashlynx WebSec Scanner engine and API gateway.

```
+─────────────────────────────────────────────────────────────────────────────+
|                         STRIDE EVALUATION MATRIX                            |
+─────────────────────────────────────────────────────────────────────────────+
| Threat Category | Potential Attack Vector     | Ashlynx Mitigation          |
+─────────────────┼─────────────────────────────┼─────────────────────────────+
| Spoofing        | Forged scan trigger         | JWT authentication + RBAC   |
| Tampering       | Scope regex modification    | Cryptographic project seal  |
| Repudiation     | Unlogged active scanning    | Immutable append-only audit |
| Information Leak| Evidence stores credentials | Automated regex redaction   |
| Denial of Serv. | Recursive crawl trap        | Depth/URL limit + loop check|
| Elevation Priv. | SSRF to Cloud Metadata      | Kernel/DNS socket pinning   |
+─────────────────────────────────────────────────────────────────────────────+
```

---

## 2. Detailed Threat Analysis & Mitigations

### 2.1 Threat 1: Scanner Weaponization via SSRF (Elevation of Privilege)
- **Vector:** An adversary instructs the scanner to scan an authorized domain that returns an HTTP 302 redirect pointing to `http://169.254.169.254/latest/meta-data/` or an internal database.
- **Impact:** Compromise of cloud instance identity and unauthorized access to cloud environment secrets.
- **Mitigation:** `ScopeGate` evaluates every redirect target. Redirects to private IP ranges or cloud metadata addresses trigger `SSRFValidationError` and abort the connection immediately before socket opening.

### 2.2 Threat 2: Time-of-Check to Time-of-Use (TOCTOU) DNS Rebinding (Tampering)
- **Vector:** An attacker configures a DNS record with a short TTL (1s) returning a valid public IP on initial check, but returning `127.0.0.1` on the second query.
- **Impact:** Scanner bypasses initial hostname validation.
- **Mitigation:** The socket connection is pinned directly to the IP resolved during pre-flight check.

### 2.3 Threat 3: Recursive Crawl Traps & Resource Exhaustion (Denial of Service)
- **Vector:** Target server dynamically generates endless synthetic URLs (e.g., `/calendar/2026/11/24/next...`).
- **Impact:** Memory exhaustion, CPU starvation, scanner lockup.
- **Mitigation:** Mandatory `max_crawl_depth` (default: 3) and `max_urls` limit (default: 500) enforced by crawler engine.
