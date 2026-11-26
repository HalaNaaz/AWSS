import hashlib
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from backend.app.scanner.active.models import ActiveFinding
from backend.app.scanner.evidence.redactor import EvidenceRedactor
from backend.app.scanner.passive.models import PassiveFinding
from shared.schemas.common import FindingStatus, Severity
from shared.schemas.discovery import TechnologyObservationSchema
from shared.schemas.finding import EndpointSchema, EvidenceSchema, FindingResponse
from shared.schemas.intelligence import EvidenceReferenceSchema


class NormalizedFinding(BaseModel):
    """Canonical intermediate finding representation across all Ashlynx detection modules."""

    id: UUID = Field(default_factory=uuid4)
    scan_id: UUID
    target_id: Optional[UUID] = None
    title: str
    description: str = ""
    vulnerability_category: str
    cwe_id: str
    owasp_category: Optional[str] = None
    severity: Severity = Severity.MEDIUM
    cvss_score: float = Field(default=5.0, ge=0.0, le=10.0)
    cvss_vector: Optional[str] = None

    affected_endpoint: str
    normalized_endpoint: str
    endpoint_path: str
    affected_parameter: Optional[str] = None
    http_method: str = "GET"

    asset_relationships: List[str] = Field(default_factory=list)
    technology_relationships: List[str] = Field(default_factory=list)

    detection_source: str = "unknown"
    detection_method: str = "unknown"
    rule_id: Optional[str] = None
    original_status: FindingStatus = FindingStatus.DETECTED
    original_confidence: float = Field(default=0.7, ge=0.0, le=1.0)

    evidence: Optional[EvidenceSchema] = None
    evidence_references: List[EvidenceReferenceSchema] = Field(default_factory=list)
    remediation_text: Optional[str] = None
    curl_reproduction: Optional[str] = None
    detection_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    fingerprint: str
    raw_module_metadata: Dict[str, Any] = Field(default_factory=dict)


class FindingNormalizer:
    """Phase 5B: Unified Finding Normalization Engine.

    Transforms findings from Passive analyzers, Active analyzers, FindingResponse objects,
    or untrusted/malformed raw dictionaries into validated NormalizedFinding instances
    with stable fingerprints and preserved forensic evidence.
    """

    CWE_PATTERN = re.compile(r"(?:CWE[-_:\s]*)?(\d{1,5})", re.IGNORECASE)

    CATEGORY_BY_CWE: Dict[str, str] = {
        "CWE-89": "SQL_INJECTION",
        "CWE-79": "XSS",
        "CWE-1336": "SSTI",
        "CWE-94": "SSTI",
        "CWE-918": "SSRF",
        "CWE-611": "XXE",
        "CWE-601": "OPEN_REDIRECT",
        "CWE-942": "CORS_MISCONFIGURATION",
        "CWE-346": "CORS_MISCONFIGURATION",
        "CWE-693": "SECURITY_HEADERS",
        "CWE-1021": "SECURITY_HEADERS",
        "CWE-614": "COOKIE_SECURITY",
        "CWE-1004": "COOKIE_SECURITY",
        "CWE-1275": "COOKIE_SECURITY",
        "CWE-200": "INFORMATION_DISCLOSURE",
        "CWE-209": "INFORMATION_DISCLOSURE",
        "CWE-319": "TRANSPORT_SECURITY",
        "CWE-311": "TRANSPORT_SECURITY",
        "CWE-287": "AUTHENTICATION_SESSION",
        "CWE-384": "AUTHENTICATION_SESSION",
        "CWE-352": "CSRF",
        "CWE-16": "MISCONFIGURATION",
        "CWE-532": "INFORMATION_DISCLOSURE",
        "CWE-22": "PATH_TRAVERSAL",
        "CWE-347": "TOKEN_SECURITY",
        "CWE-613": "TOKEN_SECURITY",
        "CWE-524": "CACHE_SECURITY",
        "CWE-525": "CACHE_SECURITY",
        "CWE-650": "API_SECURITY",
        "CWE-436": "API_SECURITY",
        "CWE-1022": "CLIENT_SIDE_SECURITY",
    }

    DEFAULT_CVSS_BY_SEVERITY: Dict[Severity, float] = {
        Severity.CRITICAL: 9.5,
        Severity.HIGH: 7.5,
        Severity.MEDIUM: 5.3,
        Severity.LOW: 3.1,
        Severity.INFORMATIONAL: 0.0,
    }

    @classmethod
    def normalize_cwe(cls, raw_cwe: Any) -> str:
        if not raw_cwe:
            return "CWE-0"
        text = str(raw_cwe).strip()
        match = cls.CWE_PATTERN.search(text)
        if match:
            return f"CWE-{match.group(1)}"
        return "CWE-0"

    @classmethod
    def normalize_severity(cls, raw_severity: Any) -> Severity:
        if isinstance(raw_severity, Severity):
            return raw_severity
        if isinstance(raw_severity, str):
            val = raw_severity.strip().upper()
            if val == "INFO":
                return Severity.INFORMATIONAL
            try:
                return Severity(val)
            except ValueError:
                pass
        return Severity.MEDIUM

    @classmethod
    def normalize_status(cls, raw_status: Any, default: FindingStatus = FindingStatus.DETECTED) -> FindingStatus:
        if isinstance(raw_status, FindingStatus):
            return raw_status
        if isinstance(raw_status, str):
            val = raw_status.strip().upper()
            try:
                return FindingStatus(val)
            except ValueError:
                pass
        return default

    @classmethod
    def normalize_url(cls, raw_url: str) -> Tuple[str, str, str]:
        """Returns (normalized_full_url, endpoint_path, host_asset)."""
        cleaned = (raw_url or "").strip()
        if not cleaned:
            return ("http://unknown/", "/", "unknown")

        if not cleaned.startswith(("http://", "https://")):
            cleaned = f"http://{cleaned.lstrip('/')}"

        try:
            parsed = urlparse(cleaned)
            scheme = (parsed.scheme or "http").lower()
            netloc = (parsed.netloc or "unknown").lower()
            path = parsed.path or "/"
            if len(path) > 1 and path.endswith("/"):
                path = path.rstrip("/")
            # Sort query parameters deterministically
            query_pairs = sorted(parse_qsl(parsed.query, keep_blank_values=True))
            query_str = urlencode(query_pairs)
            norm_url = urlunparse((scheme, netloc, path, "", query_str, ""))
            return (norm_url, path, netloc)
        except Exception:
            return (cleaned, "/", "unknown")

    @classmethod
    def classify_category(cls, cwe_id: str, title: str, rule_id: Optional[str] = None) -> str:
        if cwe_id in cls.CATEGORY_BY_CWE:
            return cls.CATEGORY_BY_CWE[cwe_id]

        combined = f"{title} {rule_id or ''}".lower()
        if "sql" in combined or "sqli" in combined:
            return "SQL_INJECTION"
        if "xss" in combined or "cross-site scripting" in combined or "script" in combined:
            return "XSS"
        if "ssti" in combined or "template" in combined:
            return "SSTI"
        if "ssrf" in combined or "request forgery" in combined and "server" in combined:
            return "SSRF"
        if "xxe" in combined or "external entity" in combined:
            return "XXE"
        if "redirect" in combined:
            return "OPEN_REDIRECT"
        if "cors" in combined or "access-control-allow" in combined:
            return "CORS_MISCONFIGURATION"
        if "cookie" in combined or "httponly" in combined or "samesite" in combined:
            return "COOKIE_SECURITY"
        if "header" in combined or "csp" in combined or "hsts" in combined or "frame" in combined:
            return "SECURITY_HEADERS"
        if "csrf" in combined or "forgery" in combined:
            return "CSRF"
        if "cleartext" in combined or "https" in combined or "tls" in combined:
            return "TRANSPORT_SECURITY"
        if "disclosure" in combined or "banner" in combined or "version" in combined or "exposure" in combined:
            return "INFORMATION_DISCLOSURE"
        if "auth" in combined or "session" in combined or "login" in combined:
            return "AUTHENTICATION_SESSION"
        return "MISCONFIGURATION"

    @classmethod
    def compute_fingerprint(
        cls,
        cwe_id: str,
        category: str,
        endpoint_path: str,
        http_method: str,
        parameter: Optional[str],
        rule_id: Optional[str] = None,
    ) -> str:
        """Computes a stable, deterministic SHA-256 fingerprint for deduplication."""
        canonical_rule = (rule_id or "").strip().lower()
        canonical_param = (parameter or "").strip().lower()
        parts = [
            cwe_id.upper(),
            category.upper(),
            endpoint_path.lower(),
            http_method.upper(),
            canonical_param,
            canonical_rule,
        ]
        payload = "|".join(parts)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]

    @classmethod
    def _build_evidence_and_refs(
        cls,
        raw_req: str,
        raw_resp: str,
        sha256_hash: Optional[str],
        probe_type: str,
        source_module: str,
        timestamp: Optional[datetime],
        existing_id: Optional[str] = None,
    ) -> Tuple[Optional[EvidenceSchema], List[EvidenceReferenceSchema]]:
        if not raw_req and not raw_resp and not sha256_hash:
            return (None, [])

        redacted_req = EvidenceRedactor.redact(raw_req or "")
        redacted_resp = EvidenceRedactor.redact(raw_resp or "")
        # Recompute SHA-256 if missing or if redaction changed unredacted content
        seal = sha256_hash if (sha256_hash and len(sha256_hash) == 64 and redacted_req == raw_req and redacted_resp == raw_resp) else EvidenceRedactor.generate_sha256_seal(redacted_req, redacted_resp)

        ev = EvidenceSchema(
            request=redacted_req,
            response=redacted_resp,
            sha256_hash=seal,
            probe_type=probe_type,
            created_at=timestamp,
        )
        ev_id = existing_id or f"ev-{seal[:12]}"
        summary = redacted_resp[:140].replace("\n", " ").strip() if redacted_resp else redacted_req[:140].strip()
        ref = EvidenceReferenceSchema(
            evidence_id=ev_id,
            sha256_hash=seal,
            probe_type=probe_type,
            source_module=source_module,
            summary=summary or None,
            timestamp=timestamp,
        )
        return (ev, [ref])

    @classmethod
    def normalize(
        cls,
        raw_finding: Union[FindingResponse, ActiveFinding, PassiveFinding, Dict[str, Any]],
        scan_id: Optional[UUID] = None,
        target_id: Optional[UUID] = None,
        technologies: Optional[List[TechnologyObservationSchema]] = None,
    ) -> NormalizedFinding:
        """Normalizes any supported finding object or raw dictionary safely."""
        resolved_scan_id = scan_id or uuid4()
        tech_names = sorted({t.technology_name for t in (technologies or []) if getattr(t, "technology_name", None)})

        if isinstance(raw_finding, ActiveFinding):
            resolved_id = raw_finding.id
            title = raw_finding.title
            description = raw_finding.description
            cwe_id = cls.normalize_cwe(raw_finding.cwe_id)
            owasp_cat = raw_finding.owasp_category
            severity = raw_finding.severity
            cvss_score = raw_finding.cvss_score
            cvss_vec = raw_finding.cvss_vector
            status = raw_finding.status
            confidence = raw_finding.confidence
            raw_url = raw_finding.url
            param = raw_finding.parameter
            method = (raw_finding.http_method or "GET").upper()
            source = raw_finding.detection_module or "active_scanner"
            det_method = "active_two_phase" if status == FindingStatus.VERIFIED else "active_probe"
            rule_id = raw_finding.rule_id
            remediation = raw_finding.remediation
            curl_repro = None
            ts = raw_finding.timestamp
            ev, ev_refs = cls._build_evidence_and_refs(
                raw_finding.evidence_request,
                raw_finding.evidence_response,
                raw_finding.evidence_hash,
                "active_probe",
                source,
                ts,
            )
            raw_meta = {
                "origin": "ActiveFinding",
                "rule_id": rule_id,
                "probe_count": raw_finding.probe_count,
                "detection_module": raw_finding.detection_module,
            }

        elif isinstance(raw_finding, PassiveFinding):
            resolved_id = raw_finding.id
            title = raw_finding.title
            description = raw_finding.description
            cwe_id = cls.normalize_cwe(raw_finding.cwe_id)
            owasp_cat = raw_finding.owasp_category
            severity = raw_finding.severity
            cvss_score = raw_finding.cvss_score
            cvss_vec = raw_finding.cvss_vector
            status = raw_finding.status
            confidence = raw_finding.confidence
            raw_url = raw_finding.url
            param = raw_finding.parameter
            method = "GET"
            source = "passive_analyzer"
            det_method = "passive_inspection"
            rule_id = raw_finding.rule_id
            remediation = raw_finding.remediation
            curl_repro = f"curl -s -I '{raw_url}'"
            ts = raw_finding.timestamp
            ev, ev_refs = cls._build_evidence_and_refs(
                raw_finding.evidence_request or f"{raw_url} [PASSIVE-ANALYSIS]",
                raw_finding.evidence_response,
                raw_finding.evidence_hash,
                "passive_analysis",
                source,
                ts,
            )
            raw_meta = {
                "origin": "PassiveFinding",
                "rule_id": rule_id,
            }

        elif isinstance(raw_finding, FindingResponse):
            resolved_id = raw_finding.id
            resolved_scan_id = scan_id or raw_finding.scan_id
            target_id = target_id or raw_finding.target_id
            title = raw_finding.title
            description = raw_finding.description or ""
            cwe_id = cls.normalize_cwe(raw_finding.cwe_id)
            owasp_cat = raw_finding.owasp_category
            severity = raw_finding.severity
            cvss_score = raw_finding.cvss_score
            cvss_vec = raw_finding.cvss_vector
            status = raw_finding.status
            confidence = raw_finding.confidence
            raw_url = raw_finding.endpoint.url if raw_finding.endpoint else "http://unknown/"
            param = raw_finding.endpoint.parameter if raw_finding.endpoint else None
            method = (raw_finding.endpoint.method if raw_finding.endpoint else "GET").upper()
            headers = (raw_finding.endpoint.headers or {}) if raw_finding.endpoint else {}
            rule_id = headers.get("evidence_rule")
            probe_type = raw_finding.evidence.probe_type if raw_finding.evidence else None
            if probe_type == "active_probe" or status in (FindingStatus.VERIFIED, FindingStatus.SUSPECTED):
                source = "active_scanner"
                det_method = "active_two_phase" if status == FindingStatus.VERIFIED else "active_probe"
            else:
                source = "passive_analyzer"
                det_method = "passive_inspection"
            remediation = raw_finding.remediation
            curl_repro = raw_finding.curl_reproduction
            ts = raw_finding.created_at
            ev_req = raw_finding.evidence.request if raw_finding.evidence else ""
            ev_resp = raw_finding.evidence.response if raw_finding.evidence else ""
            ev_hash = raw_finding.evidence.sha256_hash if raw_finding.evidence else None
            ev, ev_refs = cls._build_evidence_and_refs(
                ev_req,
                ev_resp,
                ev_hash,
                probe_type or "primary",
                source,
                ts,
            )
            raw_meta = {
                "origin": "FindingResponse",
                "rule_id": rule_id,
                "endpoint_headers": headers,
            }

        elif isinstance(raw_finding, dict):
            # Defensive normalization of malformed or external dicts
            try:
                resolved_id = UUID(str(raw_finding["id"])) if raw_finding.get("id") else uuid4()
            except Exception:
                resolved_id = uuid4()

            if raw_finding.get("scan_id"):
                try:
                    resolved_scan_id = UUID(str(raw_finding["scan_id"]))
                except Exception:
                    pass

            if raw_finding.get("target_id") and not target_id:
                try:
                    target_id = UUID(str(raw_finding["target_id"]))
                except Exception:
                    pass

            raw_title = str(raw_finding.get("title") or "Untitled Security Observation").strip()
            title = raw_title[:200] if len(raw_title) >= 3 else f"Finding: {raw_title}".ljust(3, "_")
            description = str(raw_finding.get("description") or "")
            cwe_id = cls.normalize_cwe(raw_finding.get("cwe_id"))
            owasp_cat = str(raw_finding.get("owasp_category")) if raw_finding.get("owasp_category") else None
            severity = cls.normalize_severity(raw_finding.get("severity"))

            raw_cvss = raw_finding.get("cvss_score")
            try:
                cvss_val = float(raw_cvss) if raw_cvss is not None else cls.DEFAULT_CVSS_BY_SEVERITY[severity]
                cvss_score = max(0.0, min(10.0, cvss_val))
            except (TypeError, ValueError):
                cvss_score = cls.DEFAULT_CVSS_BY_SEVERITY[severity]

            cvss_vec = str(raw_finding["cvss_vector"]) if raw_finding.get("cvss_vector") else None
            status = cls.normalize_status(raw_finding.get("status"))

            raw_conf = raw_finding.get("confidence", 0.5)
            try:
                confidence = max(0.0, min(1.0, float(raw_conf)))
            except (TypeError, ValueError):
                confidence = 0.5

            ep_obj = raw_finding.get("endpoint") if isinstance(raw_finding.get("endpoint"), dict) else {}
            raw_url = str(ep_obj.get("url") or raw_finding.get("url") or "http://unknown/")
            param = ep_obj.get("parameter") or raw_finding.get("parameter")
            if param is not None:
                param = str(param).strip() or None
            method = str(ep_obj.get("method") or raw_finding.get("http_method") or raw_finding.get("method") or "GET").upper()[:10]

            source = str(raw_finding.get("detection_module") or raw_finding.get("detection_source") or "external_import")
            det_method = str(raw_finding.get("detection_method") or "heuristic_import")
            rule_id = str(raw_finding["rule_id"]) if raw_finding.get("rule_id") else None
            remediation = str(raw_finding["remediation"]) if raw_finding.get("remediation") else None
            curl_repro = str(raw_finding["curl_reproduction"]) if raw_finding.get("curl_reproduction") else None
            ts = datetime.now(timezone.utc)

            ev_dict = raw_finding.get("evidence") if isinstance(raw_finding.get("evidence"), dict) else {}
            ev_req = str(ev_dict.get("request") or raw_finding.get("evidence_request") or "")
            ev_resp = str(ev_dict.get("response") or raw_finding.get("evidence_response") or "")
            ev_hash = ev_dict.get("sha256_hash") or raw_finding.get("evidence_hash")
            probe_type = str(ev_dict.get("probe_type") or "imported")
            ev, ev_refs = cls._build_evidence_and_refs(ev_req, ev_resp, ev_hash, probe_type, source, ts)
            raw_meta = {
                "origin": "dict",
                "keys": sorted(str(k) for k in raw_finding.keys()),
            }
        else:
            raise TypeError(f"Unsupported finding input type: {type(raw_finding).__name__}")

        norm_url, endpoint_path, host_asset = cls.normalize_url(raw_url)
        category = cls.classify_category(cwe_id, title, rule_id)
        fingerprint = cls.compute_fingerprint(
            cwe_id=cwe_id,
            category=category,
            endpoint_path=endpoint_path,
            http_method=method,
            parameter=param,
            rule_id=rule_id,
        )

        asset_rels = [host_asset] if host_asset and host_asset != "unknown" else []

        return NormalizedFinding(
            id=resolved_id,
            scan_id=resolved_scan_id,
            target_id=target_id,
            title=title,
            description=description,
            vulnerability_category=category,
            cwe_id=cwe_id,
            owasp_category=owasp_cat,
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vec,
            affected_endpoint=raw_url,
            normalized_endpoint=norm_url,
            endpoint_path=endpoint_path,
            affected_parameter=param,
            http_method=method,
            asset_relationships=asset_rels,
            technology_relationships=tech_names,
            detection_source=source,
            detection_method=det_method,
            rule_id=rule_id,
            original_status=status,
            original_confidence=confidence,
            evidence=ev,
            evidence_references=ev_refs,
            remediation_text=remediation,
            curl_reproduction=curl_repro,
            detection_timestamp=ts,
            fingerprint=fingerprint,
            raw_module_metadata=raw_meta,
        )

    @classmethod
    def normalize_batch(
        cls,
        raw_findings: List[Any],
        scan_id: Optional[UUID] = None,
        target_id: Optional[UUID] = None,
        technologies: Optional[List[TechnologyObservationSchema]] = None,
    ) -> List[NormalizedFinding]:
        """Normalizes a list of findings while skipping unrecoverable corrupt records safely."""
        results: List[NormalizedFinding] = []
        for item in raw_findings:
            try:
                results.append(
                    cls.normalize(
                        item,
                        scan_id=scan_id,
                        target_id=target_id,
                        technologies=technologies,
                    )
                )
            except Exception:
                continue
        return results
