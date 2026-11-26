import hashlib
import re
from typing import Dict, Any


class EvidenceRedactor:
    """Sanitizes sensitive data from HTTP traces before storage.
    
    Prevents password, session token, and credit card leaks in evidence records.
    """

    REDACTION_PATTERNS = [
        # Authorization header
        (re.compile(r'(Authorization:\s*(?:Bearer|Basic)\s+)[^\r\n]+', re.IGNORECASE), r'\1[REDACTED]'),
        # Sensitive query string parameters (?token=, &api_key=, &access_token=, etc.)
        (re.compile(r'([?&](?:access_token|refresh_token|id_token|api_key|apikey|token|secret|password|auth)=)[^&\s\r\n]+', re.IGNORECASE), r'\1[REDACTED]'),
        # Session and auth cookies in headers (Cookie and Set-Cookie)
        (re.compile(r'(\b(?:session|token|auth|jwt|sid|id)[A-Za-z0-9_.-]*=)[^;\r\n&\s]+', re.IGNORECASE), r'\1[REDACTED]'),
        # JSON fields: password, secret, token, api_key
        (re.compile(r'("(?:password|secret|token|api_key|access_token|refresh_token)"\s*:\s*")[^"]+(")', re.IGNORECASE), r'\1[REDACTED]\2'),
        # Key-Value assignments in config/.env files
        (re.compile(r'(^\s*[A-Za-z0-9_.-]*(?:SECRET|KEY|PASSWORD|TOKEN|PASS|PWD|AUTH|CREDENTIAL)[A-Za-z0-9_.-]*\s*=\s*)[^\r\n]+', re.IGNORECASE | re.MULTILINE), r'\1[REDACTED]'),
        # Private Keys
        (re.compile(r'-----BEGIN [A-Z ]+PRIVATE KEY-----[^-]+-----END [A-Z ]+PRIVATE KEY-----', re.DOTALL), '[REDACTED_PRIVATE_KEY]'),
        # Credit Card Numbers (16 digits with dashes or spaces)
        (re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b'), '[REDACTED_CREDIT_CARD]')
    ]

    @classmethod
    def redact(cls, text: str) -> str:
        """Applies all redaction rules to input text."""
        if not text:
            return ""
        redacted = text
        for pattern, replacement in cls.REDACTION_PATTERNS:
            redacted = pattern.sub(replacement, redacted)
        return redacted

    @classmethod
    def generate_sha256_seal(cls, request_data: str, response_data: str) -> str:
        """Computes cryptographic SHA-256 integrity seal for an evidence pair."""
        hasher = hashlib.sha256()
        hasher.update(request_data.encode("utf-8", errors="replace"))
        hasher.update(b"---EVIDENCE_BOUNDARY---")
        hasher.update(response_data.encode("utf-8", errors="replace"))
        return hasher.hexdigest()
