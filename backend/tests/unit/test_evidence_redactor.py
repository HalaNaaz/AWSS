from backend.app.scanner.evidence.redactor import EvidenceRedactor


def test_evidence_redaction_authorization_headers():
    raw_req = "GET /api/me HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer secret-token-xyz123\r\n\r\n"
    redacted = EvidenceRedactor.redact(raw_req)
    assert "secret-token-xyz123" not in redacted
    assert "Authorization: Bearer [REDACTED]" in redacted


def test_evidence_redaction_cookies():
    raw_req = "POST /api/action HTTP/1.1\r\nHost: example.com\r\nCookie: session=super_secret_session_abc; other=val\r\n\r\n"
    redacted = EvidenceRedactor.redact(raw_req)
    assert "super_secret_session_abc" not in redacted
    assert "session=[REDACTED]" in redacted


def test_evidence_redaction_json_passwords():
    raw_body = '{"username": "admin", "password": "MySuperSecretPassword123!"}'
    redacted = EvidenceRedactor.redact(raw_body)
    assert "MySuperSecretPassword123!" not in redacted
    assert '"password": "[REDACTED]"' in redacted


def test_evidence_sha256_seal_integrity():
    req = "GET / HTTP/1.1\r\nHost: example.com\r\n"
    resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
    seal1 = EvidenceRedactor.generate_sha256_seal(req, resp)
    seal2 = EvidenceRedactor.generate_sha256_seal(req, resp)

    assert len(seal1) == 64
    assert seal1 == seal2

    # Modified request yields different hash
    seal3 = EvidenceRedactor.generate_sha256_seal(req + "Extra", resp)
    assert seal1 != seal3
