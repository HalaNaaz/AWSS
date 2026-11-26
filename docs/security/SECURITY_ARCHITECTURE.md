# Security Architecture Specification

**Document Identifier:** SEC-WSS-2026-V1.0  
**Parent Specification:** Master PRD (`PRD-WSS-2026-V2.0-FINAL`)

---

## 1. Scanner Self-Defense & Invariants
A dynamic security scanner is by definition an active network testing engine. It must be engineered with defensive guardrails to ensure it cannot be weaponized against internal networks or abused as an open proxy.

### 1.1 Non-Bypassable Anti-SSRF Socket Pinning
1. Target URLs are parsed and their hostnames are resolved using an explicit custom DNS resolution step.
2. The resolved IP is evaluated against all prohibited ranges:
   - RFC 1918 Private Ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
   - Carrier-Grade NAT (`100.64.0.0/10`, RFC 6598) and Benchmarking / IANA Protocol Ranges (`192.0.0.0/24`, `198.18.0.0/15`, RFC 2544)
   - Loopback (`127.0.0.0/8`, `::1/128`)
   - Cloud Metadata (`169.254.169.254`, `169.254.0.0/16`, `fe80::/10`) and IPv6 Documentation (`2001:db8::/32`)
   - IPv4-Mapped IPv6 (`::ffff:0:0/96` unwrapped against prohibited IPv4 CIDRs)
   - Multicast & Broadcast (`224.0.0.0/4`, `240.0.0.0/4`)
3. The socket connection is pinned directly to the verified IP address, defeating DNS rebinding attacks.

### 1.2 Strict Scope Boundary Enforcement
- All discovered links and extracted JavaScript routes pass through `ScopeGate.validate_url_in_scope()` before any request is scheduled.
- Out-of-scope third-party origins (e.g., external OAuth providers, analytics scripts) are dropped from the active queue.

### 1.3 In-Memory Credential & PII Redaction
- `Authorization: Bearer ...` and `Basic ...` tokens are masked as `[REDACTED]`.
- Sensitive URL query parameters (`access_token`, `refresh_token`, `id_token`, `api_key`, `apikey`, `token`, `secret`, `password`, `auth`) are masked as `[REDACTED]`.
- Session cookies (`session=...`, `jwt=...`) are masked.
- JSON body fields with sensitive keys (`password`, `secret`, `token`, `api_key`) are masked before persistence and across JSON/Markdown/HTML/SARIF exports.

### 1.4 Cryptographic Evidence Sealing
- Evidence pairs (request + response) are digested using SHA-256 to produce an immutable integrity seal.

### 1.5 Local API Boundary & Token Guard
- The API gateway binds to `127.0.0.1` (`HOST=127.0.0.1`, `ENFORCE_LOCAL_BOUNDARY=True`) by default for single-workstation safety.
- Requests arriving with non-loopback client/forwarded addresses without an authorized token are rejected with HTTP `403` (`LOCAL_BOUNDARY_VIOLATION`).
- When `API_AUTH_TOKEN` is configured, all `/api/v1/*` endpoints require matching `Authorization: Bearer <token>` or `X-API-Key: <token>` credentials (HTTP `401` otherwise), while `/healthz` remains accessible for liveness probes.
