# PHASE 3: SECURITY REGRESSION MATRIX

**Document Identifier:** REG-MATRIX-WSS-2026-PHASE3-V1.0  
**Audit Reference:** `AUDIT-WSS-2026-PHASE3-V1.0`  
**Date:** 2026-11-25  

---

## 1. Regression Test Matrix

| Req ID | Security Requirement | Component | Test Case | Expected Behavior | Pre-Remediation Status | Post-Remediation Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **SEC-REQ-01** | Authorization Safety Gate | `endpoints/active.py` | `test_sec_req_01_mandatory_authorization_confirmation` | API must reject probe requests lacking verified target ownership or authorization token. | **FAILED** (accepted client boolean) | **VERIFIED (PASSED)** |
| **SEC-REQ-02** | Scope Boundary Enforcement | `endpoints/active.py` | `test_sec_req_02_scope_enforcement_prevents_private_ip` | Probing out-of-scope or unauthorized external hosts must be rejected with 400 Bad Request. | **FAILED** (accepted arbitrary URL) | **VERIFIED (PASSED)** |
| **SEC-REQ-03** | Socket-Level IP Pinning | `crawler/client.py` | `test_sec_req_03_socket_ip_pinning_in_client` | Outbound TCP socket must connect directly to `pinned_ip`, preventing TOCTOU DNS rebinding. | **FAILED** (pinned IP discarded) | **VERIFIED (PASSED)** |
| **SEC-REQ-04** | Complete DNS IP Validation | `scope/scope_gate.py` | `test_sec_req_04_dns_all_addrinfo_records_checked` | All resolved A and AAAA records must be checked; any prohibited IP causes rejection. | **FAILED** (only checked index 0) | **VERIFIED (PASSED)** |
| **SEC-REQ-05** | HTTP Client Method Support | `crawler/client.py` | `test_sec_req_05_client_supports_generic_request_methods` | Client must support `request()` with OPTIONS, POST, PUT, HEAD with full ScopeGate validation. | **FAILED** (missing `.request()`) | **VERIFIED (PASSED)** |
| **SEC-REQ-06** | Open Redirect Detection | `analyzers/misconfiguration.py` | `test_sec_req_06_open_redirect_non_following_behavior` | Open redirect must be detected on 3xx responses without automatically navigating out-of-scope. | **FAILED** (blocked or followed) | **VERIFIED (PASSED)** |
| **SEC-REQ-07** | Non-HTML XSS Suppression | `analyzers/xss.py` | `test_sec_req_07_xss_non_html_content_type_no_false_positive` | Canary reflection in JSON or plain text must NOT be classified as HTML-context XSS. | **FAILED** (false positive flagged) | **VERIFIED (PASSED)** |
| **SEC-REQ-08** | Evidence Redaction | `analyzers/misconfiguration.py`, `authentication.py` | `test_sec_req_08_evidence_redaction_secrets_and_cookies` | Exposed passwords in `.env` and `Set-Cookie` tokens must be redacted in stored evidence. | **FAILED** (raw text stored) | **VERIFIED (PASSED)** |
| **SEC-REQ-09** | Dynamic Page SQLi Stability | `analyzers/sqli.py` | `test_sec_req_09_sqli_boolean_resists_micro_fluctuations` | Dynamic timestamps/nonces must not trigger false positive boolean SQLi findings. | **FAILED** (len delta >= 10 flagged) | **VERIFIED (PASSED)** |
| **SEC-REQ-10** | Safe Method Validation | `endpoints/active.py` | `test_sec_req_10_probe_method_validation` | Disallowed HTTP methods (e.g. TRACE, CONNECT) must be rejected with 400 Bad Request. | **FAILED** (accepted arbitrary method) | **VERIFIED (PASSED)** |
