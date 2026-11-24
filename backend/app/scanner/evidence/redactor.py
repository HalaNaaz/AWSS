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
        # Session and auth cookies
        (re.compile(r'((?:session|token|auth|jwt|sid)=)[^;\r\n]+', re.IGNORECASE), r'\1[REDACTED]'),
        # JSON fields: password, secret, token, api_key
        (re.compile(r'("(?:password|secret|token|api_key|access_token|refresh_token)"\s*:\s*")[^"]+(")', re.IGNORECASE), r'\1[REDACTED]\2'),
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
