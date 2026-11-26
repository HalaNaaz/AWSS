from collections import Counter
from typing import Dict, List, Optional
from uuid import UUID

from shared.schemas.common import Severity
from shared.schemas.phase6 import (
    ScanAnalyticsSchema,
    ScanComparisonSchema,
    ScanTrendPointSchema,
    SecurityCoverageReportSchema,
)
from shared.schemas.report import UnifiedScanReport


class SecurityAnalyticsEngine:
    """Phase 6G: Real-Data Security Assessment Analytics & Scan Comparison Engine.

    Computes multi-scan distributions, coverage trends, technology-risk patterns,
    endpoint exposure breakdowns, and baseline-vs-current scan diffs exclusively
    from persisted/registered scan telemetry (zero synthetic data).
    """

    @classmethod
    def compute_analytics(
        cls,
        reports: List[UnifiedScanReport],
        coverage_by_scan: Optional[Dict[UUID, SecurityCoverageReportSchema]] = None,
    ) -> ScanAnalyticsSchema:
        if not reports:
            return ScanAnalyticsSchema()

        cov_map = coverage_by_scan or {}
        sev_counter: Counter = Counter()
        val_counter: Counter = Counter()
        prio_counter: Counter = Counter()
        cat_counter: Counter = Counter()
        tech_counter: Counter = Counter()
        exposure_counter: Counter = Counter()
        trends: List[ScanTrendPointSchema] = []
        cov_values: List[float] = []
        total_findings = 0

        sorted_reports = sorted(reports, key=lambda r: r.created_at)

        for r in sorted_reports:
            total_findings += len(r.findings)
            crit_high = 0
            unique_prim = 0

            for f in r.findings:
                sev_counter[f.severity.value] += 1
                if f.severity in (Severity.CRITICAL, Severity.HIGH):
                    crit_high += 1

                if f.intelligence:
                    if f.intelligence.is_primary:
                        unique_prim += 1
                    val_counter[f.intelligence.validation_state.value] += 1
                    prio_counter[f.intelligence.contextual_risk.contextual_priority.value] += 1
                    cat_counter[f.intelligence.vulnerability_category] += 1
                    for tech in f.intelligence.technology_relationships:
                        tech_counter[tech] += 1
                    path = f.intelligence.normalized_endpoint.lower()
                    if any(k in path for k in ("/api/", "/graphql", "/v1/", "/v2/")):
                        exposure_counter["API_EXPOSED"] += 1
                    elif any(k in path for k in ("/login", "/auth", "/admin")):
                        exposure_counter["AUTH_SENSITIVE"] += 1
                    else:
                        exposure_counter["STANDARD_WEB"] += 1
                else:
                    unique_prim += 1
                    val_counter[f.status.value] += 1

            cov_obj = cov_map.get(r.scan_id) or getattr(r, "security_coverage", None)
            cov_pct = cov_obj.overall_dast_coverage_percent if cov_obj else 0.0
            if cov_obj:
                cov_values.append(cov_pct)

            trends.append(ScanTrendPointSchema(
                scan_id=r.scan_id,
                target_url=r.target_url,
                created_at=r.created_at,
                status=r.status,
                total_findings=len(r.findings),
                unique_primary_findings=unique_prim,
                critical_high_count=crit_high,
                coverage_percent=cov_pct,
                duration_seconds=r.duration_seconds,
            ))

        avg_cov = round(sum(cov_values) / len(cov_values), 1) if cov_values else 0.0

        return ScanAnalyticsSchema(
            total_scans_analyzed=len(sorted_reports),
            total_findings_across_scans=total_findings,
            severity_distribution=dict(sev_counter),
            validation_lifecycle_distribution=dict(val_counter),
            contextual_priority_distribution=dict(prio_counter),
            top_vulnerable_categories=dict(cat_counter.most_common(10)),
            technology_risk_patterns=dict(tech_counter.most_common(10)),
            endpoint_exposure_breakdown=dict(exposure_counter),
            average_dast_coverage_percent=avg_cov,
            scan_trends=trends,
        )

    @classmethod
    def compare_scans(
        cls,
        baseline: UnifiedScanReport,
        current: UnifiedScanReport,
        baseline_cov: Optional[SecurityCoverageReportSchema] = None,
        current_cov: Optional[SecurityCoverageReportSchema] = None,
    ) -> ScanComparisonSchema:
        """Compares two scans using AVIVE finding fingerprints to identify new, resolved, and persisting findings."""
        def _fp_set(rep: UnifiedScanReport) -> set[str]:
            fps: set[str] = set()
            for f in rep.findings:
                if f.intelligence and f.intelligence.fingerprint:
                    fps.add(f.intelligence.fingerprint)
                else:
                    ep = f.endpoint.url if f.endpoint else ""
                    fps.add(f"{f.cwe_id}|{ep}|{f.title}")
            return fps

        base_fps = _fp_set(baseline)
        curr_fps = _fp_set(current)

        new_fps = sorted(curr_fps - base_fps)
        resolved_fps = sorted(base_fps - curr_fps)
        persisting_fps = sorted(base_fps & curr_fps)

        b_cov_obj = baseline_cov or getattr(baseline, "security_coverage", None)
        c_cov_obj = current_cov or getattr(current, "security_coverage", None)
        cov_delta = round((c_cov_obj.overall_dast_coverage_percent if c_cov_obj else 0.0) - (b_cov_obj.overall_dast_coverage_percent if b_cov_obj else 0.0), 1)

        summary = (
            f"Comparison ({str(baseline.scan_id)[:8]} -> {str(current.scan_id)[:8]}): "
            f"{len(new_fps)} new, {len(resolved_fps)} resolved, {len(persisting_fps)} persisting findings "
            f"(coverage delta: {cov_delta:+.1f}%)."
        )

        return ScanComparisonSchema(
            baseline_scan_id=baseline.scan_id,
            current_scan_id=current.scan_id,
            baseline_target_url=baseline.target_url,
            current_target_url=current.target_url,
            new_findings_count=len(new_fps),
            resolved_findings_count=len(resolved_fps),
            persisting_findings_count=len(persisting_fps),
            new_finding_fingerprints=new_fps,
            resolved_finding_fingerprints=resolved_fps,
            persisting_finding_fingerprints=persisting_fps,
            coverage_delta_percent=cov_delta,
            summary=summary,
        )
