# Security Architecture & Safeguards

## 1. Non-Bypassable Scope & Anti-SSRF Controls (`ScopeGate`)

Every outbound scanner connection passes through [`backend/app/scanner/scope/scope_gate.py`](../backend/app/scanner/scope/scope_gate.py) and [`backend/app/scanner/crawler/client.py`](../backend/app/scanner/crawler/client.py):
- **Pre-Flight URL Validation:** Rejects non-`http`/`https` schemes and malformed hostnames before DNS or `pin_map` lookup, and discards out-of-scope URLs against inclusion/exclusion regex rules.
- **Prohibited Network Ranges:** Blocks all resolved A/AAAA records intersecting:
  - RFC 1918 private networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
  - Loopback (`127.0.0.0/8`, `::1/128`) and unspecified (`0.0.0.0/8`, `::/128`)
  - Cloud metadata & link-local (`169.254.0.0/16`, `fe80::/10`)
  - Carrier-Grade NAT (`100.64.0.0/10`, RFC 6598), benchmarking (`198.18.0.0/15`, RFC 2544), IANA protocol (`192.0.0.0/24`), and IPv6 documentation (`2001:db8::/32`)
  - IPv4-mapped IPv6 bypasses (`::ffff:0:0/96`, explicitly unwrapped and checked against IPv4 CIDRs)
  - Multicast & reserved blocks (`224.0.0.0/4`, `240.0.0.0/4`, `fc00::/7`)
- **Socket IP Pinning (`PinningNetworkBackend`):** Binds TCP connections directly to the pre-validated IP address to prevent Time-of-Check to Time-of-Use (TOCTOU) DNS rebinding.
- **Redirect Hop Re-Validation:** Disables automatic HTTP redirects (`follow_redirects=False`) and re-validates every hop through `ScopeGate`.

`ALLOW_PRIVATE_IPS` defaults to `false` and should only be enabled for isolated local test fixtures.

---

## 2. Authorization Safety Gates & Non-Destructive Scanning

- **Mandatory Consent:** CLI scans require `--authorized` (`-a`); API active probing (`POST /api/v1/active/probe`) rejects `"authorized": false` with HTTP `403`.
- **Two-Phase Deterministic Verification:** Suspected anomalies remain `SUSPECTED / UNVERIFIED` unless verified by deterministic secondary probes (SQLi boolean invariant `AND 8943=8943` vs `AND 8943=8944`, unescaped XSS canary execution, safe mathematical SSTI probes, or safe traversal differentials).
- **DoS & State Safety:** `RequestBudgetTracker`, crawl depth/URL caps, rate-limiting with backoff on HTTP `429`, non-mutating probe allowlists (`GET`, `POST`, `HEAD`, `OPTIONS` — rejecting `PUT`/`DELETE`), and exclusion of `/logout`/`/delete` routes prevent unintended damage.

---

## 3. Evidence Redaction, Integrity & API Boundary

- **In-Memory PII/Secret Scrubbing (`EvidenceRedactor`):** Masks `Authorization` Bearer/Basic headers, sensitive query parameters (`access_token`, `refresh_token`, `id_token`, `api_key`, `token`, `secret`, `password`, `auth`), session cookies, JSON secret fields, `.env` credential assignments, private keys, and credit cards across stored evidence and JSON/HTML/Markdown/SARIF reports.
- **Cryptographic Chain of Custody:** Request/response evidence pairs are hashed with SHA-256 (`generate_sha256_seal`).
- **XSS-Safe Reporting:** `HTMLReportGenerator` escapes dynamic fields with `html.escape()`, and the UI renders HTML previews inside `<iframe sandbox="">`.
- **Workstation API Boundary (`LocalBoundaryAndAuthMiddleware`):**
  - Default bind is loopback `HOST=127.0.0.1` (`ENFORCE_LOCAL_BOUNDARY=true`), rejecting remote/proxied traffic without authentication (`403 LOCAL_BOUNDARY_VIOLATION`).
  - When `API_AUTH_TOKEN` is configured, all `/api/v1/*` routes validate Bearer / `X-API-Key` tokens in constant time (`401` on mismatch), while `/healthz` remains open for liveness probes.

---

## 4. Known Scope Constraints

- **Local Workstation Mode:** Multi-tenant authentication/RBAC and PostgreSQL/Redis persistence are scoped to `V3` per [`PRD.md`](../PRD.md). Current local runs retain scan state in memory (`ScanLifecycleRegistry`, bounded at `100` jobs).
- **Responsible Use:** Never point AWSS at third-party infrastructure without explicit authorization. Report security issues responsibly through repository maintainers.
