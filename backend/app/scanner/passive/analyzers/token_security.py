import base64
import json
import re
from typing import Any, Dict, List, Optional, Tuple

from backend.app.scanner.passive.base import BasePassiveAnalyzer
from backend.app.scanner.passive.models import HTTPResponseContext, PassiveFinding
from shared.schemas.common import Severity, FindingStatus


class TokenSecurityAnalyzer(BasePassiveAnalyzer):
    """Passive analyzer for JWT structure, weak token claims, and bearer tokens exposed in URLs."""

    analyzer_id = "AUTH-TOKEN-ANALYZER"
    analyzer_name = "JWT & Authentication Token Hygiene Analyzer"
    category = "Authentication & Token Security"
    supported_rules = [
        "PASSIVE-JWT-ALG-NONE",
        "PASSIVE-JWT-WEAK-CLAIMS",
        "PASSIVE-AUTH-BEARER-QUERY",
    ]

    JWT_PATTERN = re.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*")
    SENSITIVE_JWT_CLAIMS = {"password", "passwd", "secret", "private_key", "ssn", "pin", "api_secret"}
    BEARER_QUERY_PATTERN = re.compile(
        r"(?:href|src|action|url)\s*[:=]\s*['\"]?[^'\"\s>]*[?&](?:access_token|auth_token|bearer|api_key|jwt)=[^&'\"\s>]{4,}",
        re.IGNORECASE,
    )

    @staticmethod
    def _b64url_json(segment: str) -> Optional[Dict[str, Any]]:
        try:
            padded = segment + "=" * (-len(segment) % 4)
            decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
            obj = json.loads(decoded.decode("utf-8"))
            return obj if isinstance(obj, dict) else None
        except Exception:
            return None

    def _inspect_jwt(self, token: str) -> Optional[Tuple[Dict[str, Any], Dict[str, Any]]]:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header = self._b64url_json(parts[0])
        payload = self._b64url_json(parts[1])
        if header is None or payload is None:
            return None
        return header, payload

    def analyze(self, context: HTTPResponseContext) -> List[PassiveFinding]:
        findings: List[PassiveFinding] = []
        candidates: List[str] = []

        for hdr_val in context.headers.values():
            candidates.extend(self.JWT_PATTERN.findall(hdr_val or ""))
        for cookie_val in context.get_all_header_values("set-cookie"):
            candidates.extend(self.JWT_PATTERN.findall(cookie_val or ""))
        if context.body:
            candidates.extend(self.JWT_PATTERN.findall(context.body[:50000]))

        seen_tokens: set[str] = set()
        for token in candidates[:10]:
            if token in seen_tokens:
                continue
            seen_tokens.add(token)
            parsed = self._inspect_jwt(token)
            if not parsed:
                continue
            header, payload = parsed
            alg = str(header.get("alg", "")).strip()

            if alg.lower() == "none":
                f = PassiveFinding(
                    rule_id="PASSIVE-JWT-ALG-NONE",
                    title="Unsecured JWT Using 'alg=none' Detected",
                    description=(
                        f"A JSON Web Token observed at '{context.url}' declares 'alg: {alg}', "
                        f"which disables cryptographic signature verification."
                    ),
                    cwe_id="CWE-347",
                    owasp_category="A07:2021 - Identification & Authentication Failures",
                    severity=Severity.HIGH,
                    cvss_score=7.5,
                    status=FindingStatus.DETECTED,
                    confidence=0.95,
                    url=context.url,
                    evidence_response=f"JWT Header: {json.dumps(header)} (token redacted)",
                    remediation="Reject 'alg=none' tokens strictly and enforce explicit asymmetric (RS256/ES256) or HS256 algorithm allowlists.",
                )
                f.seal_evidence()
                findings.append(f)

            exposed_sensitive = sorted(k for k in payload.keys() if k.lower() in self.SENSITIVE_JWT_CLAIMS)
            missing_exp = "exp" not in payload
            if missing_exp or exposed_sensitive:
                reasons: List[str] = []
                if missing_exp:
                    reasons.append("missing 'exp' expiration claim")
                if exposed_sensitive:
                    reasons.append(f"sensitive cleartext claim keys: {', '.join(exposed_sensitive)}")
                f = PassiveFinding(
                    rule_id="PASSIVE-JWT-WEAK-CLAIMS",
                    title="Weak JWT Claim Hygiene Observed",
                    description=f"A JWT observed at '{context.url}' exhibits weak claim hygiene ({'; '.join(reasons)}).",
                    cwe_id="CWE-613" if missing_exp else "CWE-200",
                    owasp_category="A07:2021 - Identification & Authentication Failures",
                    severity=Severity.MEDIUM if exposed_sensitive else Severity.LOW,
                    cvss_score=5.3 if exposed_sensitive else 3.7,
                    status=FindingStatus.DETECTED,
                    confidence=0.90,
                    url=context.url,
                    evidence_response=f"JWT Claims Keys: {sorted(payload.keys())} (values redacted)",
                    remediation="Include short-lived 'exp' claims on all JWTs and never embed secrets, passwords, or PII in unencrypted JWT payloads.",
                )
                f.seal_evidence()
                findings.append(f)

        if context.body:
            match = self.BEARER_QUERY_PATTERN.search(context.body[:50000])
            if match:
                f = PassiveFinding(
                    rule_id="PASSIVE-AUTH-BEARER-QUERY",
                    title="Authentication Token or API Key Embedded in URL Query Parameter",
                    description=(
                        f"Response content from '{context.url}' embeds an authentication token or API key in a URL query string, "
                        f"exposing credentials to logs, browser history, and Referer headers."
                    ),
                    cwe_id="CWE-598",
                    owasp_category="A07:2021 - Identification & Authentication Failures",
                    severity=Severity.MEDIUM,
                    cvss_score=5.3,
                    status=FindingStatus.DETECTED,
                    confidence=0.88,
                    url=context.url,
                    evidence_response=f"Matched URL reference (token redacted): {match.group(0).split('=')[0]}=[REDACTED]",
                    remediation="Transmit bearer tokens and API keys in HTTP Authorization headers rather than URL query parameters.",
                )
                f.seal_evidence()
                findings.append(f)

        return findings
