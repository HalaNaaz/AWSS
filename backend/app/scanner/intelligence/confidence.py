import re
from typing import Any, Dict, List, Optional

from backend.app.scanner.intelligence.normalizer import NormalizedFinding
from shared.schemas.common import FindingStatus, Severity
from shared.schemas.intelligence import (
    ConfidenceAssessmentSchema,
    ConfidenceFactorSchema,
    ConfidenceLevel,
    CorrelationRelationship,
)


class ConfidenceEngine:
    """Phase 5D: Transparent Evidence Quality & Confidence Assessment Engine.

    Computes explainable confidence classifications (LOW, MEDIUM, HIGH) from
    structured evidence criteria rather than opaque heuristics, ensuring
    confidence is strictly separated from vulnerability severity.
    """

    CONTRADICTION_PATTERNS = [
        (re.compile(r"\b(cloudflare|akamai|imperva|mod_security|waf\s*block)\b", re.IGNORECASE), "WAF or security filter interception signature in response"),
        (re.compile(r"\b(403\s+forbidden|406\s+not\s+acceptable|429\s+too\s+many\s+requests)\b", re.IGNORECASE), "HTTP access denial or rate-limiting status detected in evidence"),
        (re.compile(r"\b(502\s+bad\s+gateway|503\s+service\s+unavailable|504\s+gateway\s+timeout)\b", re.IGNORECASE), "Upstream gateway availability error in evidence"),
    ]

    ACTIVE_INJECTION_CATEGORIES = {"SQL_INJECTION", "XSS", "SSTI", "SSRF", "XXE", "PATH_TRAVERSAL"}

    @classmethod
    def assess(
        cls,
        finding: NormalizedFinding,
        correlation_info: Optional[Dict[str, Any]] = None,
        has_parameter_intel: bool = False,
    ) -> ConfidenceAssessmentSchema:
        """Evaluates structured evidence quality factors and returns an explainable ConfidenceAssessmentSchema."""
        factors: List[ConfidenceFactorSchema] = []
        contributing: List[str] = []
        missing: List[str] = []
        contradictions: List[str] = []

        # 1. Detection Method Reliability (Weight: 0.25)
        if finding.detection_method == "active_two_phase" and finding.original_status == FindingStatus.VERIFIED:
            m_score, m_status = 1.0, "POSITIVE"
            m_detail = "Verified by deterministic two-phase active validation probe."
            contributing.append(m_detail)
        elif finding.detection_method == "passive_inspection" and finding.vulnerability_category in (
            "SECURITY_HEADERS",
            "COOKIE_SECURITY",
            "CORS_MISCONFIGURATION",
            "TRANSPORT_SECURITY",
            "INFORMATION_DISCLOSURE",
            "CACHE_SECURITY",
            "TOKEN_SECURITY",
            "CLIENT_SIDE_SECURITY",
        ):
            m_score, m_status = 0.85, "POSITIVE"
            m_detail = "Direct deterministic header/attribute observation from HTTP transaction."
            contributing.append(m_detail)
        elif finding.detection_method == "active_probe":
            m_score, m_status = 0.50, "NEUTRAL"
            m_detail = "Single-phase active anomaly probe without secondary deterministic confirmation."
            missing.append("Secondary deterministic verification probe")
        else:
            m_score, m_status = 0.35, "NEUTRAL"
            m_detail = f"Heuristic or imported detection method ({finding.detection_method})."
            missing.append("Direct scanner verification proof")

        factors.append(ConfidenceFactorSchema(
            factor="detection_method_reliability",
            score=m_score,
            weight=0.25,
            status=m_status,
            detail=m_detail,
        ))

        # 2. Reproducibility (Weight: 0.20)
        has_curl = bool(finding.curl_reproduction)
        has_endpoint_pin = bool(finding.normalized_endpoint and finding.normalized_endpoint != "http://unknown/")
        if finding.original_status == FindingStatus.VERIFIED and has_endpoint_pin:
            r_score, r_status = 1.0, "POSITIVE"
            r_detail = "Deterministically reproducible against pinned endpoint and parameter."
            contributing.append(r_detail)
        elif has_endpoint_pin and (has_curl or finding.affected_parameter or finding.rule_id):
            r_score, r_status = 0.80, "POSITIVE"
            r_detail = "Reproducible HTTP target endpoint and rule/parameter vector captured."
            contributing.append("Pinned HTTP request vector captured")
        elif has_endpoint_pin:
            r_score, r_status = 0.50, "NEUTRAL"
            r_detail = "Endpoint recorded, but parameter or exact reproduction trace is incomplete."
            missing.append("Explicit reproduction command or parameter pin")
        else:
            r_score, r_status = 0.15, "MISSING"
            r_detail = "Target endpoint URL missing or unresolvable."
            missing.append("Valid target endpoint URL")

        factors.append(ConfidenceFactorSchema(
            factor="reproducibility",
            score=r_score,
            weight=0.20,
            status=r_status,
            detail=r_detail,
        ))

        # 3. Evidence Completeness (Weight: 0.20)
        has_seal = bool(finding.evidence and len(finding.evidence.sha256_hash) == 64)
        has_req = bool(finding.evidence and finding.evidence.request.strip())
        has_resp = bool(finding.evidence and finding.evidence.response.strip())
        if has_seal and has_req and has_resp:
            e_score, e_status = 1.0, "POSITIVE"
            e_detail = "Complete redacted request/response evidence pair with SHA-256 integrity seal."
            contributing.append("SHA-256 sealed HTTP request and response trace present")
        elif has_seal and (has_req or has_resp):
            e_score, e_status = 0.70, "POSITIVE"
            e_detail = "Partial HTTP trace with SHA-256 seal (missing request or response body)."
            missing.append("Full paired request + response HTTP trace")
        else:
            e_score, e_status = 0.10, "MISSING"
            e_detail = "No cryptographic HTTP evidence trace attached."
            missing.append("Cryptographically sealed HTTP evidence")

        factors.append(ConfidenceFactorSchema(
            factor="evidence_completeness",
            score=e_score,
            weight=0.20,
            status=e_status,
            detail=e_detail,
        ))

        # 4. Signal Quality (Weight: 0.15)
        if finding.original_status == FindingStatus.VERIFIED:
            s_score, s_status = 1.0, "POSITIVE"
            s_detail = "High-precision verification signal confirmed payload evaluation or boundary violation."
        elif finding.original_confidence >= 0.85 and finding.rule_id:
            s_score, s_status = 0.85, "POSITIVE"
            s_detail = f"High-signal deterministic rule match ({finding.rule_id})."
        elif finding.original_confidence >= 0.65:
            s_score, s_status = 0.65, "NEUTRAL"
            s_detail = "Moderate heuristic signal; anomaly observed without conclusive proof."
        else:
            s_score, s_status = 0.35, "NEUTRAL"
            s_detail = "Weak/speculative detection signal."
            missing.append("Strong deterministic vulnerability indicator")

        factors.append(ConfidenceFactorSchema(
            factor="signal_quality",
            score=s_score,
            weight=0.15,
            status=s_status,
            detail=s_detail,
        ))

        # 5. Response Consistency & Contradictory Evidence Check (Weight: 0.10)
        resp_text = finding.evidence.response if finding.evidence else ""
        if resp_text:
            for pattern, msg in cls.CONTRADICTION_PATTERNS:
                # Note: 403 on auth boundary tests or missing headers on intentionally 403 pages might still be informational,
                # but for active injection claims it contradicts execution confidence.
                if pattern.search(resp_text):
                    if finding.vulnerability_category in cls.ACTIVE_INJECTION_CATEGORIES or "waf" in msg.lower():
                        contradictions.append(msg)

        if contradictions:
            c_score, c_status = 0.15, "NEGATIVE"
            c_detail = "; ".join(contradictions)
        elif has_resp:
            c_score, c_status = 0.90, "POSITIVE"
            c_detail = "Response headers/body consistent with reported finding without WAF/throttle contradictions."
            contributing.append("Consistent HTTP response telemetry")
        else:
            c_score, c_status = 0.40, "MISSING"
            c_detail = "No HTTP response available to verify consistency."
            missing.append("HTTP response payload for consistency check")

        factors.append(ConfidenceFactorSchema(
            factor="response_consistency",
            score=c_score,
            weight=0.10,
            status=c_status,
            detail=c_detail,
        ))

        # 6. Independent Corroboration (Weight: 0.10)
        rel_ids = (correlation_info or {}).get("related_finding_ids", [])
        rel_type = (correlation_info or {}).get("correlation_relationship", CorrelationRelationship.INDEPENDENT)
        corroborated = bool(rel_ids) or has_parameter_intel or (rel_type in (CorrelationRelationship.DUPLICATE, CorrelationRelationship.RELATED))
        if corroborated:
            k_score, k_status = 1.0, "POSITIVE"
            k_detail = "Corroborated by multi-signal correlation or attack surface parameter intelligence."
            contributing.append(k_detail)
        else:
            k_score, k_status = 0.50, "NEUTRAL"
            k_detail = "Single-source observation; no independent corroborating module signal."

        factors.append(ConfidenceFactorSchema(
            factor="independent_corroboration",
            score=k_score,
            weight=0.10,
            status=k_status,
            detail=k_detail,
        ))

        # Weighted aggregate score
        total_score = round(sum(f.score * f.weight for f in factors), 3)
        total_score = max(0.0, min(1.0, total_score))

        # Classify strictly using transparent thresholds and safety guards
        is_unverified_active_injection = (
            finding.vulnerability_category in cls.ACTIVE_INJECTION_CATEGORIES
            and finding.original_status != FindingStatus.VERIFIED
        )

        if contradictions or total_score < 0.50:
            level = ConfidenceLevel.LOW
        elif is_unverified_active_injection:
            # Non-verified active injection cannot be classified HIGH confidence
            level = ConfidenceLevel.MEDIUM if total_score >= 0.50 else ConfidenceLevel.LOW
        elif total_score >= 0.78:
            level = ConfidenceLevel.HIGH
        elif total_score >= 0.50:
            level = ConfidenceLevel.MEDIUM
        else:
            level = ConfidenceLevel.LOW

        # Determine whether manual review is required
        needs_manual_review = (
            level == ConfidenceLevel.LOW
            or bool(contradictions)
            or is_unverified_active_injection
            or (finding.severity in (Severity.CRITICAL, Severity.HIGH) and level != ConfidenceLevel.HIGH)
        )

        # Build concise explanation
        if level == ConfidenceLevel.HIGH:
            explanation = (
                f"HIGH confidence ({total_score:.2f}): Supported by {len(contributing)} strong evidence signals "
                f"with complete SHA-256 sealed traces and zero contradictions."
            )
        elif level == ConfidenceLevel.MEDIUM:
            reason_extra = " Unverified active injection probe requires confirmation." if is_unverified_active_injection else ""
            explanation = (
                f"MEDIUM confidence ({total_score:.2f}): Observable evidence present, but gaps remain "
                f"({len(missing)} missing criteria).{reason_extra}"
            )
        else:
            explanation = (
                f"LOW confidence ({total_score:.2f}): Insufficient evidence or contradictory signals detected; "
                f"manual analyst verification required before treating as confirmed."
            )

        return ConfidenceAssessmentSchema(
            level=level,
            score=total_score,
            factors=factors,
            contributing_evidence=contributing,
            missing_evidence=missing,
            contradictory_signals=contradictions,
            corroborated=corroborated,
            needs_manual_review=needs_manual_review,
            explanation=explanation,
        )
