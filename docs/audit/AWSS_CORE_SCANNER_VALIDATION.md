# AWSS-CORE — SCANNER ENGINE & CLI VALIDATION REPORT

## 1. Analyzer Inventory & Live Validation
- **Registered Analyzers:** `8` Active (`ActivePluginRegistry`) and `9` Passive (`PassiveAnalysisEngine`).
- **Controlled Target Fixture (`http://127.0.0.1:8089`):**
  - Synchronous `SAFE_ACTIVE` scan completed in `2.59s`, yielding `91` normalized findings (`99` in full E2E workflow) across `XSS` (`CWE-79`), `OPEN_REDIRECT` (`CWE-601`), `SECURITY_HEADERS`, `INFORMATION_DISCLOSURE`, `TRANSPORT_SECURITY`, and `CACHE_SECURITY`.
- **Phase 7 Live Defect Discovered & Remediated:**
  - `PathTraversalAnalyzer` and `APISecurityAnalyzer` passed invalid `scan_id=...` kwarg and failed to unpack `(resp, err)` tuples from `AsyncHTTPClient`. Because unit tests mocked a permissive single-return `client.get`, both analyzers silently threw `TypeError` in real scans.
  - **Post-fix live verification** against real `AsyncHTTPClient`: `APISecurityAnalyzer` detected `ACT-API-SWAGGER-EXPOSED` on `http://127.0.0.1:8089/openapi.json` (`1` finding), and `PathTraversalAnalyzer` executed `3` HTTP probes cleanly.

## 2. CLI Live Validation (`python -m cli.ashlynx.main`)
| Command | Expected RC | Observed RC | Details |
|---|---:|---:|---|
| `--help` | 0 | 0 | Command help rendered |
| `version` | 0 | 0 | Rich banner rendered |
| `scan http://127.0.0.1:8089` (no `-a`) | 2 | 2 | Safety Gate violation enforced |
| `scan http://127.0.0.1:8089 -a --profile BAD_PROF` | 2 | 2 | Profile validation enforced |
| `scan ftp://bad -a` | 2 | 2 | Scheme validation enforced |
| `scan http://127.0.0.1:8089 -a -p quick-assessment -f json -o audit_evidence/logs/cli_scan_report.json` | 0 | 0 | Scan completed & valid JSON report written |
