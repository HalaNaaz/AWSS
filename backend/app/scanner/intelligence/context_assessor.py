import hashlib
from collections import defaultdict
from typing import Dict, List, Optional
from uuid import UUID

from backend.app.scanner.discovery.engine import AttackSurfaceIntelligenceEngine
from shared.schemas.discovery import ParameterCategory, ParameterIntelligenceSchema
from shared.schemas.finding import FindingResponse
from shared.schemas.phase6 import (
    ContextAssessmentReportSchema,
    ContextAssessmentSuggestionSchema,
)


class ContextAwareAssessor:
    """Phase 6C: Context-Aware Assessment Suggestion Engine.

    Combines Attack Surface Intelligence (endpoints, parameters, APIs, technologies),
    authentication context, and AVIVE findings/confidence to produce actionable,
    non-destructive assessment recommendations strictly within authorized scope.
    """

    @classmethod
    def evaluate(
        cls,
        scan_id: UUID,
        discovery_engine: Optional[AttackSurfaceIntelligenceEngine],
        findings: List[FindingResponse],
    ) -> ContextAssessmentReportSchema:
        if not discovery_engine:
            return ContextAssessmentReportSchema(
                scan_id=scan_id,
                evaluated_endpoints=0,
                evaluated_parameters=0,
                suggestions=[],
                summary="No attack surface discovery telemetry available for context assessment.",
            )

        endpoints = discovery_engine.endpoint_engine.get_endpoints()
        parameters = discovery_engine.parameter_engine.get_parameters()
        apis = discovery_engine.api_engine.get_api_endpoints()
        techs = [t.technology_name for t in discovery_engine.technologies]

        params_by_url: Dict[str, List[ParameterIntelligenceSchema]] = defaultdict(list)
        for p in parameters:
            for u in p.endpoints_found:
                params_by_url[u.lower()].append(p)

        findings_by_url: Dict[str, List[FindingResponse]] = defaultdict(list)
        for f in findings:
            if f.endpoint:
                findings_by_url[f.endpoint.url.lower()].append(f)

        suggestions: List[ContextAssessmentSuggestionSchema] = []

        # 1. Parameter & Auth Boundary Suggestions
        for ep in endpoints:
            norm = ep.normalized_url.lower()
            ep_params = params_by_url.get(norm, [])
            ep_findings = findings_by_url.get(norm, [])
            param_cats = {p.category for p in ep_params}

            if ParameterCategory.REDIRECT in param_cats:
                suggestions.append(cls._make_suggestion(
                    url=ep.url,
                    category="OPEN_REDIRECT_SSRF_BOUNDARY",
                    priority="HIGH",
                    check="Verify strict allowlist validation on redirect/URL parameter without auto-following redirects.",
                    rationale="Redirect parameter detected; unvalidated targets enable phishing or SSRF pivoting.",
                    signals=["ParameterCategory.REDIRECT"] + ([f"Tech:{techs[0]}"] if techs else []),
                    related_count=len(ep_findings),
                ))

            if ParameterCategory.AUTH in param_cats or any(k in norm for k in ("/login", "/auth", "/account")):
                suggestions.append(cls._make_suggestion(
                    url=ep.url,
                    category="AUTH_SESSION_HARDENING",
                    priority="HIGH",
                    check="Verify anti-CSRF token enforcement, Secure/HttpOnly/SameSite cookie attributes, and rate limiting.",
                    rationale="Authentication boundary endpoint handles credentials or session issuance.",
                    signals=["AuthBoundaryRoute"],
                    related_count=len(ep_findings),
                ))

            if ParameterCategory.SEARCH in param_cats or ParameterCategory.IDENTIFIER in param_cats:
                low_conf = [
                    f for f in ep_findings
                    if f.intelligence and f.intelligence.confidence_assessment.needs_manual_review
                ]
                if low_conf or not ep_findings:
                    suggestions.append(cls._make_suggestion(
                        url=ep.url,
                        category="INPUT_SANITIZATION_VERIFICATION",
                        priority="MEDIUM",
                        check="Run non-destructive differential boolean/canary verification on search/identifier parameters.",
                        rationale="Dynamic query/identifier parameter warrants deterministic injection resistance confirmation.",
                        signals=[f"Params:{','.join(p.name for p in ep_params[:3])}"],
                        related_count=len(ep_findings),
                    ))

        # 2. Unauthenticated API Exposure Suggestions
        for api in apis:
            if not api.auth_required:
                suggestions.append(cls._make_suggestion(
                    url=api.url,
                    category="PUBLIC_API_ACCESS_CONTROL",
                    priority="MEDIUM",
                    check="Confirm whether unauthenticated access to API endpoint is intentional and review CORS/rate-limits.",
                    rationale=f"Detected {api.api_type.value} API endpoint without apparent authentication requirement.",
                    signals=[f"APIType:{api.api_type.value}", "auth_required=False"],
                    related_count=len(findings_by_url.get(api.url.lower(), [])),
                ))

        # Deduplicate suggestions by suggestion_id preserving order
        deduped: Dict[str, ContextAssessmentSuggestionSchema] = {}
        for s in suggestions:
            if s.suggestion_id not in deduped:
                deduped[s.suggestion_id] = s

        final_list = list(deduped.values())
        return ContextAssessmentReportSchema(
            scan_id=scan_id,
            evaluated_endpoints=len(endpoints),
            evaluated_parameters=len(parameters),
            suggestions=final_list,
            summary=(
                f"Generated {len(final_list)} context-aware assessment recommendations across "
                f"{len(endpoints)} endpoints and {len(parameters)} parameters."
            ),
        )

    @staticmethod
    def _make_suggestion(
        url: str,
        category: str,
        priority: str,
        check: str,
        rationale: str,
        signals: List[str],
        related_count: int,
    ) -> ContextAssessmentSuggestionSchema:
        sid = hashlib.sha256(f"{url}|{category}".encode("utf-8")).hexdigest()[:12]
        return ContextAssessmentSuggestionSchema(
            suggestion_id=f"ctx-{sid}",
            target_url=url,
            category=category,
            priority=priority,
            recommended_safe_check=check,
            rationale=rationale,
            context_signals=signals,
            related_existing_findings=related_count,
        )
