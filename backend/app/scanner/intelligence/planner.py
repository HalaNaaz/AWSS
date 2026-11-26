from collections import defaultdict
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse
from uuid import UUID

from backend.app.scanner.active.registry import ActivePluginRegistry, active_plugin_registry
from backend.app.scanner.discovery.engine import AttackSurfaceIntelligenceEngine
from backend.app.scanner.scope.scope_gate import ScopeGate
from shared.schemas.common import ScanProfile
from shared.schemas.discovery import EndpointCategory, ParameterCategory, ParameterIntelligenceSchema
from shared.schemas.phase6 import (
    PlannedTargetCheckSchema,
    ScanPlanSchema,
    SkippedTargetCheckSchema,
)
from shared.schemas.scan import SCAN_PROFILE_PRESETS


class IntelligentScanPlanner:
    """Phase 6B: Explainable, Scope-Locked Intelligent Scan Planner.

    Inspects discovered attack surface telemetry, technologies, parameter categories,
    and profile constraints to prioritize relevant non-destructive active checks and
    prune redundant probes without ever expanding target scope.
    """

    STATIC_CATEGORIES = {
        EndpointCategory.CSS,
        EndpointCategory.IMAGE,
        EndpointCategory.JAVASCRIPT,
        EndpointCategory.DOCUMENT,
    }

    STATIC_EXTENSIONS = (".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".pdf")

    @classmethod
    def build_plan(
        cls,
        scan_id: UUID,
        target_url: str,
        profile: ScanProfile,
        scope_gate: ScopeGate,
        discovery_engine: Optional[AttackSurfaceIntelligenceEngine] = None,
        registry: Optional[ActivePluginRegistry] = None,
        request_budget: Optional[int] = None,
        rate_limit_rps: Optional[float] = None,
        enabled_modules: Optional[Set[str]] = None,
    ) -> ScanPlanSchema:
        reg = registry or active_plugin_registry
        preset = SCAN_PROFILE_PRESETS.get(profile, SCAN_PROFILE_PRESETS[ScanProfile.QUICK_ASSESSMENT])
        resolved_budget = request_budget if request_budget is not None else int(preset.get("request_budget", 0))
        resolved_rps = rate_limit_rps if rate_limit_rps is not None else float(preset.get("rate_limit_rps", 10.0))

        analyzers = reg.get_analyzers_for_profile(profile, enabled_modules)
        analyzer_ids = {a.analyzer_id for a in analyzers}

        tech_names: List[str] = []
        endpoints = []
        params_by_url: Dict[str, List[ParameterIntelligenceSchema]] = defaultdict(list)

        if discovery_engine:
            tech_names = sorted({t.technology_name for t in discovery_engine.technologies})
            endpoints = list(discovery_engine.endpoint_engine.get_endpoints())
            for p in discovery_engine.parameter_engine.get_parameters():
                for ep_url in p.endpoints_found:
                    params_by_url[ep_url.lower()].append(p)

        planned: List[PlannedTargetCheckSchema] = []
        skipped: List[SkippedTargetCheckSchema] = []

        if not analyzers or resolved_budget <= 0:
            return ScanPlanSchema(
                scan_id=scan_id,
                target_url=target_url,
                profile=profile,
                total_discovered_endpoints=len(endpoints),
                planned_targets_count=0,
                skipped_targets_count=len(endpoints),
                allocated_probe_budget=resolved_budget,
                estimated_total_probes=0,
                rate_limit_rps=resolved_rps,
                scope_enforced=True,
                technologies_context=tech_names,
                planned_checks=[],
                skipped_checks=[
                    SkippedTargetCheckSchema(
                        url=target_url,
                        analyzer_or_category="ACTIVE_DETECTION",
                        reason=f"Profile '{profile.value}' runs in passive-only / zero active probe budget mode.",
                    )
                ],
                planner_summary=f"Passive-only scan plan generated for profile {profile.value}; 0 active probes scheduled.",
            )

        # Build prioritized lookup if discovery engine is available
        prio_scores: Dict[str, float] = {}
        if discovery_engine:
            for prio in discovery_engine.get_prioritized_endpoints():
                prio_scores[prio.url.lower()] = prio.priority_score

        remaining_budget = resolved_budget
        seen_urls: Set[str] = set()
        candidates = list(endpoints)
        # Sort highest priority endpoints first
        candidates.sort(key=lambda ep: prio_scores.get(ep.normalized_url.lower(), 10.0), reverse=True)

        for ep in candidates:
            url = ep.url
            norm_url = ep.normalized_url
            if norm_url in seen_urls:
                continue
            seen_urls.add(norm_url)

            # Non-bypassable ScopeGate check
            if not scope_gate.validate_url_in_scope(url):
                skipped.append(SkippedTargetCheckSchema(
                    url=url,
                    analyzer_or_category="ALL",
                    reason="Excluded by ScopeGate target boundary or SSRF policy.",
                ))
                continue

            path_lower = urlparse(norm_url).path.lower()
            if ep.endpoint_category in cls.STATIC_CATEGORIES or path_lower.endswith(cls.STATIC_EXTENSIONS):
                skipped.append(SkippedTargetCheckSchema(
                    url=url,
                    analyzer_or_category="ACTIVE_INJECTION",
                    reason=f"Static asset ({ep.endpoint_category.value}) pruned to avoid redundant active probes.",
                ))
                continue

            ep_params = params_by_url.get(norm_url.lower(), [])
            has_query_or_body = bool(ep.query_params or ep_params or ep.method.upper() in ("POST", "PUT", "PATCH"))
            param_cats = {p.category for p in ep_params}

            selected: List[str] = []
            reasons: List[str] = []

            if "ACT-SQLI-ANALYZER" in analyzer_ids and has_query_or_body:
                selected.append("ACT-SQLI-ANALYZER")
                reasons.append("input parameters present for boolean SQLi check")

            if "ACT-XSS-ANALYZER" in analyzer_ids and has_query_or_body:
                selected.append("ACT-XSS-ANALYZER")
                reasons.append("query/form inputs eligible for inert XSS canary check")

            if "ACT-SSRF-ANALYZER" in analyzer_ids and (
                ParameterCategory.REDIRECT in param_cats
                or ParameterCategory.URL in param_cats
                or "redirect" in path_lower
                or "fetch" in path_lower
                or "proxy" in path_lower
            ):
                selected.append("ACT-SSRF-ANALYZER")
                reasons.append("URL/redirect parameter or proxy route detected")

            if "ACT-XXE-ANALYZER" in analyzer_ids and (
                (ep.content_type and "xml" in ep.content_type.lower())
                or ep.endpoint_category == EndpointCategory.API
            ):
                selected.append("ACT-XXE-ANALYZER")
                reasons.append("API/XML-capable endpoint")

            if "ACT-AUTH-ANALYZER" in analyzer_ids and (
                ParameterCategory.AUTH in param_cats
                or ParameterCategory.SESSION in param_cats
                or any(k in path_lower for k in ("login", "auth", "session", "admin", "account"))
            ):
                selected.append("ACT-AUTH-ANALYZER")
                reasons.append("authentication or session boundary route")

            if "ACT-MISCONFIG-ANALYZER" in analyzer_ids and (
                ep.crawl_depth <= 1 or ep.endpoint_category in (EndpointCategory.API, EndpointCategory.PAGE)
            ):
                selected.append("ACT-MISCONFIG-ANALYZER")
                reasons.append("surface misconfiguration / SSTI / redirect check")

            if not selected:
                skipped.append(SkippedTargetCheckSchema(
                    url=url,
                    analyzer_or_category="ACTIVE_INJECTION",
                    reason="No input parameters, auth boundaries, or eligible attack vectors observed.",
                ))
                continue

            est_probes = min(remaining_budget, len(selected) * 3)
            if est_probes <= 0:
                skipped.append(SkippedTargetCheckSchema(
                    url=url,
                    analyzer_or_category=",".join(selected),
                    reason=f"Skipped due to request budget exhaustion ({resolved_budget} probes allocated).",
                ))
                continue

            remaining_budget -= est_probes
            planned.append(PlannedTargetCheckSchema(
                url=url,
                method=ep.method.upper(),
                priority_score=prio_scores.get(norm_url.lower(), 20.0),
                selected_analyzers=selected,
                estimated_probes=est_probes,
                rationale="; ".join(reasons),
            ))

        est_total = sum(p.estimated_probes for p in planned)
        summary = (
            f"Planned {len(planned)} active targets ({est_total}/{resolved_budget} probe budget) "
            f"across {len(endpoints)} discovered endpoints; pruned {len(skipped)} redundant/out-of-scope checks."
        )
        return ScanPlanSchema(
            scan_id=scan_id,
            target_url=target_url,
            profile=profile,
            total_discovered_endpoints=len(endpoints),
            planned_targets_count=len(planned),
            skipped_targets_count=len(skipped),
            allocated_probe_budget=resolved_budget,
            estimated_total_probes=est_total,
            rate_limit_rps=resolved_rps,
            scope_enforced=True,
            technologies_context=tech_names,
            planned_checks=planned,
            skipped_checks=skipped,
            planner_summary=summary,
        )
