from typing import Any, Dict, List, Optional

from backend.app.scanner.intelligence.normalizer import NormalizedFinding
from shared.schemas.common import Severity
from shared.schemas.discovery import APIEndpointSchema, ParameterCategory, ParameterIntelligenceSchema
from shared.schemas.intelligence import (
    ConfidenceAssessmentSchema,
    ConfidenceLevel,
    ContextualPriority,
    ContextualRiskAssessmentSchema,
    CorrelationRelationship,
    RiskFactorSchema,
)


class ContextualRiskEngine:
    """Phase 5F: Intelligent Contextual Risk Assessment Engine.

    Evaluates contextual factors (exposure, auth requirements, parameter sensitivity,
    technology stack, cluster correlation, confidence, and optional analyst-configured
    asset criticality) without overwriting or altering intrinsic CVSS scores or severity.
    """

    SEVERITY_BASE_POINTS: Dict[Severity, float] = {
        Severity.CRITICAL: 92.0,
        Severity.HIGH: 76.0,
        Severity.MEDIUM: 52.0,
        Severity.LOW: 28.0,
        Severity.INFORMATIONAL: 10.0,
    }

    CONFIDENCE_MULTIPLIER: Dict[ConfidenceLevel, float] = {
        ConfidenceLevel.HIGH: 1.00,
        ConfidenceLevel.MEDIUM: 0.85,
        ConfidenceLevel.LOW: 0.55,
    }

    HIGH_RISK_PARAM_CATEGORIES = {
        ParameterCategory.AUTH,
        ParameterCategory.SESSION,
        ParameterCategory.REDIRECT,
        ParameterCategory.FILE,
        ParameterCategory.IDENTIFIER,
        ParameterCategory.SENSITIVE,
    }

    @classmethod
    def assess(
        cls,
        finding: NormalizedFinding,
        confidence_assessment: ConfidenceAssessmentSchema,
        correlation_info: Optional[Dict[str, Any]] = None,
        asset_criticality: Optional[float] = None,
        endpoint_apis: Optional[List[APIEndpointSchema]] = None,
        endpoint_parameters: Optional[List[ParameterIntelligenceSchema]] = None,
    ) -> ContextualRiskAssessmentSchema:
        """Computes transparent contextual risk score (0-100) and priority separately from CVSS."""
        factors: List[RiskFactorSchema] = []
        data_limitations: List[str] = []

        # 1. Intrinsic Severity & CVSS Baseline (Weight: 0.40)
        sev_pts = cls.SEVERITY_BASE_POINTS.get(finding.severity, 50.0)
        cvss_pts = finding.cvss_score * 10.0
        intrinsic_score = (sev_pts * 0.6) + (cvss_pts * 0.4)
        factors.append(RiskFactorSchema(
            factor="severity_cvss_baseline",
            weight=0.40,
            raw_value=f"{finding.severity.value} (CVSS {finding.cvss_score:.1f})",
            contribution=round(intrinsic_score * 0.40, 2),
            rationale="Baseline technical impact derived from severity and CVSS score.",
        ))

        # 2. Evidence Confidence Factor (Weight: 0.20)
        conf_mult = cls.CONFIDENCE_MULTIPLIER[confidence_assessment.level]
        conf_component = confidence_assessment.score * 100.0 * conf_mult
        factors.append(RiskFactorSchema(
            factor="evidence_confidence",
            weight=0.20,
            raw_value=f"{confidence_assessment.level.value} ({confidence_assessment.score:.2f})",
            contribution=round(conf_component * 0.20, 2),
            rationale="Confidence attenuates speculative alerts so low-confidence findings do not dominate triage.",
        ))

        # 3. Endpoint Exposure & Auth Context (Weight: 0.15)
        matching_api = None
        if endpoint_apis:
            for api in endpoint_apis:
                if api.url.lower() == finding.normalized_endpoint.lower():
                    matching_api = api
                    break

        if matching_api:
            if not matching_api.auth_required:
                exp_score = 90.0
                exp_raw = f"Public API ({matching_api.api_type.value}, auth_required=False)"
                exp_rat = "Unauthenticated API endpoint increases external exploitability."
            else:
                exp_score = 55.0
                exp_raw = f"Auth-protected API ({matching_api.api_type.value})"
                exp_rat = "Requires authentication, reducing anonymous attack exposure."
        elif any(k in finding.endpoint_path.lower() for k in ("/login", "/auth", "/admin", "/search", "/api")):
            exp_score = 80.0
            exp_raw = "High-exposure interactive route"
            exp_rat = "Endpoint path serves authentication, administrative, or query functionality."
        else:
            exp_score = 60.0
            exp_raw = "Standard web route (auth boundary unknown)"
            exp_rat = "Standard HTTP endpoint exposure assumed; explicit auth state not observed."
            data_limitations.append("Explicit authentication enforcement could not be confirmed from passive headers alone.")

        factors.append(RiskFactorSchema(
            factor="endpoint_exposure",
            weight=0.15,
            raw_value=exp_raw,
            contribution=round(exp_score * 0.15, 2),
            rationale=exp_rat,
        ))

        # 4. Asset Criticality (Weight: 0.15) — Never fabricated if unknown
        if asset_criticality is not None:
            # Analyst supplied 0.5 .. 5.0 scale -> normalize to 0..100
            clamped_crit = max(0.5, min(5.0, float(asset_criticality)))
            crit_score = (clamped_crit / 5.0) * 100.0
            crit_raw = f"{clamped_crit:.1f} / 5.0 (analyst-configured)"
            crit_rat = "Reflects explicit analyst-assigned business criticality for this target."
            used_crit: Optional[float] = clamped_crit
        else:
            crit_score = 40.0
            crit_raw = "Unconfigured (neutral baseline)"
            crit_rat = "Asset criticality was not supplied; neutral baseline applied without fabrication."
            used_crit = None
            data_limitations.append("Asset criticality not configured by analyst; using neutral baseline weight.")

        factors.append(RiskFactorSchema(
            factor="asset_criticality",
            weight=0.15,
            raw_value=crit_raw,
            contribution=round(crit_score * 0.15, 2),
            rationale=crit_rat,
        ))

        # 5. Attack Surface & Correlation Amplification (Weight: 0.10)
        amp_score = 30.0
        amp_reasons: List[str] = []

        if endpoint_parameters:
            risky_params = [p for p in endpoint_parameters if p.category in cls.HIGH_RISK_PARAM_CATEGORIES]
            if risky_params:
                amp_score += 35.0
                amp_reasons.append(f"sensitive params ({', '.join(p.name for p in risky_params[:3])})")

        rel_ids = (correlation_info or {}).get("related_finding_ids", [])
        rel_type = (correlation_info or {}).get("correlation_relationship", CorrelationRelationship.INDEPENDENT)
        if rel_type == CorrelationRelationship.RELATED and rel_ids:
            amp_score += 25.0
            amp_reasons.append(f"{len(rel_ids)} related co-located findings")

        if finding.technology_relationships:
            amp_score += 10.0
            amp_reasons.append(f"tech stack mapped ({', '.join(finding.technology_relationships[:2])})")

        amp_score = min(100.0, amp_score)
        amp_raw = "; ".join(amp_reasons) if amp_reasons else "Isolated single-node observation"
        factors.append(RiskFactorSchema(
            factor="attack_surface_context",
            weight=0.10,
            raw_value=amp_raw,
            contribution=round(amp_score * 0.10, 2),
            rationale="Amplifies priority when findings co-occur with sensitive parameters or related flaws.",
        ))

        contextual_score = round(sum(f.contribution for f in factors), 1)
        contextual_score = max(0.0, min(100.0, contextual_score))

        # Map score to priority with confidence safety cap
        if contextual_score >= 82.0:
            priority = ContextualPriority.CRITICAL
        elif contextual_score >= 64.0:
            priority = ContextualPriority.HIGH
        elif contextual_score >= 42.0:
            priority = ContextualPriority.MEDIUM
        elif contextual_score >= 20.0:
            priority = ContextualPriority.LOW
        else:
            priority = ContextualPriority.INFO

        # Guard: Do not let LOW confidence findings trigger CRITICAL/HIGH automated triage priority
        if confidence_assessment.level == ConfidenceLevel.LOW and priority in (ContextualPriority.CRITICAL, ContextualPriority.HIGH):
            priority = ContextualPriority.MEDIUM
            data_limitations.append("Contextual priority capped at MEDIUM pending validation of LOW confidence evidence.")

        rationale = (
            f"Contextual priority {priority.value} (score {contextual_score}/100) evaluated from "
            f"{finding.severity.value} severity, {confidence_assessment.level.value} confidence, "
            f"and {exp_raw.lower()}."
        )

        return ContextualRiskAssessmentSchema(
            contextual_priority=priority,
            contextual_score=contextual_score,
            severity_baseline=finding.severity,
            cvss_baseline=finding.cvss_score,
            confidence_level=confidence_assessment.level,
            asset_criticality_used=used_crit,
            risk_factors=factors,
            priority_rationale=rationale,
            data_limitations=data_limitations,
        )
