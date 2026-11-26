import asyncio
from datetime import datetime, timezone
import time
from typing import Optional, List, Dict, Tuple, Any, Set
from uuid import UUID, uuid4

from backend.app.core.logging import logger
from backend.app.scanner.reconnaissance.orchestrator import ReconOrchestrator
from backend.app.scanner.crawler.client import AsyncHTTPClient
from backend.app.scanner.active import ActiveDetectionEngine, ActiveTarget
from backend.app.scanner.discovery.engine import AttackSurfaceIntelligenceEngine
from backend.app.scanner.intelligence.engine import VulnerabilityIntelligenceEngine
from backend.app.scanner.intelligence.planner import IntelligentScanPlanner
from backend.app.scanner.intelligence.context_assessor import ContextAwareAssessor
from backend.app.scanner.intelligence.coverage import SecurityCoverageEngine
from backend.app.scanner.intelligence.evidence_intel import EvidenceIntelligenceEngine
from backend.app.scanner.active.registry import active_plugin_registry
from shared.schemas.common import ScanProfile, ScanStatus, ScopeRuleType
from shared.schemas.discovery import (
    ReconSummaryResponse,
    AttackSurfaceSummarySchema,
    AttackSurfaceGraphSchema,
    PrioritizedEndpointSchema,
    ParameterIntelligenceSchema,
    APIEndpointSchema,
    AssetIntelligenceSchema
)
from shared.schemas.finding import FindingResponse
from shared.schemas.intelligence import ScanIntelligenceSummarySchema
from shared.schemas.phase6 import (
    ContextAssessmentReportSchema,
    EvidenceIntelligenceSummarySchema,
    ExecutionReliabilityMetricsSchema,
    ScanPlanSchema,
    SecurityCoverageReportSchema,
)
from shared.schemas.report import UnifiedScanReport, SeveritySummarySchema
from shared.schemas.scan import SCAN_PROFILE_PRESETS, ScanJobResponse, ScanJobCreate


class ScanOrchestrator:
    """Master Scan Lifecycle Orchestrator for Ashlynx WebSec Scanner.
    
    Coordinates discovery, crawling, passive analysis, and unified report generation
    through strict lifecycle state transitions:
    QUEUED -> RUNNING -> COMPLETED (or FAILED / CANCELLED).
    """

    def __init__(
        self,
        target_url: str,
        scan_id: Optional[UUID] = None,
        profile: ScanProfile = ScanProfile.QUICK_ASSESSMENT,
        scope_rules: Optional[List[Tuple[ScopeRuleType, str]]] = None,
        max_crawl_depth: Optional[int] = None,
        max_urls: Optional[int] = None,
        concurrency: Optional[int] = None,
        rate_limit_rps: Optional[float] = None,
        respect_robots: bool = True,
        analyze_javascript: bool = True,
        target_id: Optional[UUID] = None,
        request_budget: Optional[int] = None,
        enabled_modules: Optional[Set[str]] = None,
        asset_criticality: Optional[float] = None,
    ):
        self.target_url = target_url.strip()
        self.scan_id = scan_id or uuid4()
        self.target_id = target_id
        self.profile = profile
        self.scope_rules = scope_rules or []
        self.respect_robots = respect_robots
        self.analyze_javascript = analyze_javascript
        self.enabled_modules = enabled_modules
        self.asset_criticality = asset_criticality

        # Resolve limits from presets with explicit override precedence
        preset = SCAN_PROFILE_PRESETS.get(profile, SCAN_PROFILE_PRESETS[ScanProfile.QUICK_ASSESSMENT])
        self.max_crawl_depth = max_crawl_depth if max_crawl_depth is not None else preset["max_crawl_depth"]
        self.max_urls = max_urls if max_urls is not None else preset["max_urls"]
        self.concurrency = concurrency if concurrency is not None else preset["concurrency"]
        self.rate_limit_rps = rate_limit_rps if rate_limit_rps is not None else preset["rate_limit_rps"]
        self.request_budget = request_budget if request_budget is not None else preset.get("request_budget", 0)

        # Lifecycle tracking
        self.status: ScanStatus = ScanStatus.QUEUED
        self.created_at: datetime = datetime.now(timezone.utc)
        self.started_at: Optional[datetime] = None
        self.completed_at: Optional[datetime] = None
        self.duration_seconds: float = 0.0
        self.error_message: Optional[str] = None

        self._recon_orchestrator: Optional[ReconOrchestrator] = None
        self._active_engine: Optional[ActiveDetectionEngine] = None
        self._recon_summary: Optional[ReconSummaryResponse] = None
        self._intelligence_summary: Optional[ScanIntelligenceSummarySchema] = None
        self._scan_plan: Optional[ScanPlanSchema] = None
        self._context_assessment: Optional[ContextAssessmentReportSchema] = None
        self._security_coverage: Optional[SecurityCoverageReportSchema] = None
        self._execution_reliability: Optional[ExecutionReliabilityMetricsSchema] = None
        self._evidence_intelligence: Optional[EvidenceIntelligenceSummarySchema] = None
        self._report: Optional[UnifiedScanReport] = None
        self._is_cancelled = False

    def cancel(self) -> None:
        """Triggers cooperative cancellation of the running scan."""
        logger.info(f"[ScanOrchestrator] Cancellation requested for scan {self.scan_id}")
        self._is_cancelled = True
        self.status = ScanStatus.CANCELLED
        if self._recon_orchestrator:
            self._recon_orchestrator.cancel()
        if self._active_engine:
            self._active_engine.cancel()

    @property
    def is_cancelled(self) -> bool:
        return self._is_cancelled

    @property
    def discovery_engine(self) -> Optional[AttackSurfaceIntelligenceEngine]:
        if self._recon_orchestrator and hasattr(self._recon_orchestrator, "discovery_engine"):
            return self._recon_orchestrator.discovery_engine
        return None

    def get_attack_surface_summary(self) -> Optional[AttackSurfaceSummarySchema]:
        eng = self.discovery_engine
        if eng:
            return eng.get_summary()
        return None

    def get_job_response(self) -> ScanJobResponse:
        """Returns the current state formatted as a ScanJobResponse."""
        findings_count = 0
        urls_crawled = 0
        if self._report:
            findings_count = len(self._report.findings)
            urls_crawled = self._report.urls_crawled
        elif self._recon_summary:
            findings_count = self._recon_summary.findings_count
            urls_crawled = self._recon_summary.urls_crawled

        return ScanJobResponse(
            id=self.scan_id,
            target_id=self.target_id,
            target_url=self.target_url,
            profile=self.profile,
            status=self.status,
            max_crawl_depth=self.max_crawl_depth,
            max_urls=self.max_urls,
            concurrency=self.concurrency,
            rate_limit_rps=self.rate_limit_rps,
            started_at=self.started_at,
            completed_at=self.completed_at,
            duration_seconds=self.duration_seconds,
            urls_crawled=urls_crawled,
            findings_count=findings_count,
            error_message=self.error_message,
            created_at=self.created_at,
        )

    async def run(self) -> UnifiedScanReport:
        """Executes the full scan lifecycle."""
        if not self.target_url:
            self.status = ScanStatus.FAILED
            self.error_message = "Target URL must not be empty."
            self.completed_at = datetime.now(timezone.utc)
            return self._build_failure_report()

        if self._is_cancelled:
            self.status = ScanStatus.CANCELLED
            self.completed_at = datetime.now(timezone.utc)
            return self._build_cancelled_report()

        # Transition: QUEUED -> RUNNING
        self.status = ScanStatus.RUNNING
        self.started_at = datetime.now(timezone.utc)
        start_time = time.perf_counter()
        logger.info(
            f"[ScanOrchestrator] Starting scan {self.scan_id} on {self.target_url} "
            f"[Profile: {self.profile.value}, Depth: {self.max_crawl_depth}, MaxURLs: {self.max_urls}]"
        )

        try:
            # Instantiate and run the reconnaissance and passive engine
            self._recon_orchestrator = ReconOrchestrator(
                target_url=self.target_url,
                scan_id=self.scan_id,
                scope_rules=self.scope_rules,
                max_depth=self.max_crawl_depth,
                max_urls=self.max_urls,
                concurrency=self.concurrency,
                rate_limit_rps=self.rate_limit_rps,
                analyze_javascript=self.analyze_javascript,
                respect_robots=self.respect_robots,
            )

            # Register live discovery engine with scan registry for API and frontend telemetry
            if self._recon_orchestrator.discovery_engine:
                scan_registry.register_discovery_engine(self.scan_id, self._recon_orchestrator.discovery_engine)

            # Check cancellation before launching
            if self._is_cancelled:
                self.status = ScanStatus.CANCELLED
                self.completed_at = datetime.now(timezone.utc)
                self.duration_seconds = round(time.perf_counter() - start_time, 2)
                return self._build_cancelled_report()

            recon_t0 = time.perf_counter()
            recon_summary = await self._recon_orchestrator.run()
            recon_dur = round(time.perf_counter() - recon_t0, 3)
            self._recon_summary = recon_summary
            stage_timings: Dict[str, float] = {"reconnaissance": recon_dur}

            # Phase 6B: Build Intelligent Scan Plan
            plan_t0 = time.perf_counter()
            self._scan_plan = IntelligentScanPlanner.build_plan(
                scan_id=self.scan_id,
                target_url=self.target_url,
                profile=self.profile,
                scope_gate=self._recon_orchestrator.scope_gate,
                discovery_engine=self.discovery_engine,
                request_budget=self.request_budget,
                rate_limit_rps=self.rate_limit_rps,
                enabled_modules=self.enabled_modules,
            )
            stage_timings["scan_planning"] = round(time.perf_counter() - plan_t0, 3)

            # Check if active vulnerability scanning is enabled for this profile
            preset = SCAN_PROFILE_PRESETS.get(self.profile, {})
            is_active_profile = preset.get("active_enabled", False) or self.profile in (
                ScanProfile.SAFE_ACTIVE,
                ScanProfile.STANDARD_ACTIVE,
                ScanProfile.FULL_ASSESSMENT,
                ScanProfile.API_TARGETED,
            )

            executed_analyzers: List[str] = []
            client_metrics: Dict[str, int] = {}

            if is_active_profile and not self._is_cancelled and recon_summary.status != "CANCELLED":
                logger.info(f"[ScanOrchestrator] Initiating active vulnerability detection phase for scan {self.scan_id}")
                act_t0 = time.perf_counter()
                targets: List[ActiveTarget] = []
                seen_urls: Set[str] = set()

                # Prioritize planned endpoints first, skipping pruned static assets
                planned_urls = {p.url for p in self._scan_plan.planned_checks}
                for ep in getattr(self._recon_orchestrator, "discovered_endpoints", []):
                    if ep.url in planned_urls and ep.url not in seen_urls:
                        seen_urls.add(ep.url)
                        targets.append(ActiveDetectionEngine.endpoint_to_active_target(ep))

                # Always ensure root target is covered if not pruned/planned
                if not targets and self.target_url not in seen_urls:
                    targets.append(ActiveTarget(url=self.target_url, method="GET"))

                self._active_engine = ActiveDetectionEngine(
                    request_budget=self.request_budget or 60,
                    concurrency=self.concurrency,
                    timeout_seconds=15.0,
                )
                executed_analyzers = [
                    a.analyzer_id
                    for a in active_plugin_registry.get_analyzers_for_profile(self.profile, self.enabled_modules)
                ]

                async with AsyncHTTPClient(
                    scope_gate=self._recon_orchestrator.scope_gate,
                    rate_limit_rps=self.rate_limit_rps,
                    max_retries=1,
                ) as active_client:
                    active_findings = await self._active_engine.run(
                        targets=targets,
                        client=active_client,
                        scan_id=self.scan_id,
                        profile=self.profile,
                        enabled_modules=self.enabled_modules,
                    )
                    client_metrics = dict(active_client.metrics)

                stage_timings["active_detection"] = round(time.perf_counter() - act_t0, 3)

                # Merge active findings with passive findings
                converted_active = [af.to_finding_response(self.scan_id) for af in active_findings]
                combined = list(recon_summary.findings or []) + converted_active

                # Record active findings in attack surface intelligence
                if self.discovery_engine:
                    for af in active_findings:
                        self.discovery_engine.record_finding(
                            finding_title=af.title,
                            endpoint_url=af.url,
                            severity=af.severity.value
                        )

                recon_summary.findings = combined
                recon_summary.findings_count = len(combined)

            # Phase 5: Execute AVIVE (Normalization, Correlation, Confidence, Validation, Risk, Remediation)
            avive_t0 = time.perf_counter()
            raw_combined = list(recon_summary.findings or [])
            enriched_findings, intel_summary = VulnerabilityIntelligenceEngine.process_findings(
                raw_findings=raw_combined,
                scan_id=self.scan_id,
                target_id=self.target_id,
                technologies=recon_summary.technologies,
                discovery_engine=self.discovery_engine,
                asset_criticality=self.asset_criticality,
            )
            recon_summary.findings = enriched_findings
            recon_summary.findings_count = len(enriched_findings)
            self._intelligence_summary = intel_summary
            stage_timings["avive_intelligence"] = round(time.perf_counter() - avive_t0, 3)

            # Phase 6C/6D/6E/6F: Context Assessment, Coverage, Evidence & Reliability Telemetry
            p6_t0 = time.perf_counter()
            self._context_assessment = ContextAwareAssessor.evaluate(
                scan_id=self.scan_id,
                discovery_engine=self.discovery_engine,
                findings=enriched_findings,
            )
            self._security_coverage = SecurityCoverageEngine.evaluate(
                scan_id=self.scan_id,
                profile=self.profile,
                findings=enriched_findings,
                scan_plan=self._scan_plan,
                passive_executed=True,
                active_analyzers_executed=executed_analyzers,
                urls_crawled=recon_summary.urls_crawled,
            )
            self._evidence_intelligence = EvidenceIntelligenceEngine.summarize(
                scan_id=self.scan_id,
                findings=enriched_findings,
            )
            stage_timings["phase6_intelligence"] = round(time.perf_counter() - p6_t0, 3)

            self.duration_seconds = round(time.perf_counter() - start_time, 2)
            self.completed_at = datetime.now(timezone.utc)

            # Check if cancelled during crawl
            if self._is_cancelled or recon_summary.status == "CANCELLED":
                self.status = ScanStatus.CANCELLED
                final_status = ScanStatus.CANCELLED
            else:
                self.status = ScanStatus.COMPLETED
                final_status = ScanStatus.COMPLETED

            err_cnt = client_metrics.get("errors", 0)
            rel_status = "CANCELLED" if self._is_cancelled else ("DEGRADED" if err_cnt > 5 else "HEALTHY")
            self._execution_reliability = ExecutionReliabilityMetricsSchema(
                scan_id=self.scan_id,
                status=final_status,
                stage_timings_seconds=stage_timings,
                total_requests_attempted=client_metrics.get("attempted", 0),
                successful_requests=client_metrics.get("succeeded", 0),
                retried_requests=client_metrics.get("retried", 0),
                timed_out_requests=client_metrics.get("timed_out", 0),
                rate_limited_429_count=client_metrics.get("rate_limited_429", 0),
                scope_blocked_count=client_metrics.get("scope_blocked", 0),
                error_count=err_cnt,
                concurrency_limit=self.concurrency,
                rate_limit_rps=self.rate_limit_rps,
                was_cancelled=self._is_cancelled,
                reliability_status=rel_status,
            )

            report = self._build_report_from_summary(recon_summary, final_status)

            self._report = report
            logger.info(
                f"[ScanOrchestrator] Scan {self.scan_id} finished in {self.duration_seconds}s with status {self.status.value}. "
                f"Findings: {len(report.findings)}"
            )
            return report

        except Exception as exc:
            self.duration_seconds = round(time.perf_counter() - start_time, 2)
            self.completed_at = datetime.now(timezone.utc)
            self.status = ScanStatus.FAILED
            self.error_message = f"Scan failed due to unhandled error: {str(exc)}"
            logger.error(f"[ScanOrchestrator] Scan {self.scan_id} failed: {exc}", exc_info=True)
            self._report = self._build_failure_report()
            return self._report

    def _build_report_from_summary(
        self, recon_summary: ReconSummaryResponse, status: ScanStatus
    ) -> UnifiedScanReport:
        findings = recon_summary.findings or []
        severity_summary = SeveritySummarySchema.from_findings(findings)

        return UnifiedScanReport(
            scan_id=self.scan_id,
            target_url=self.target_url,
            profile=self.profile,
            status=status,
            created_at=self.created_at,
            started_at=self.started_at,
            completed_at=self.completed_at,
            duration_seconds=self.duration_seconds,
            urls_crawled=recon_summary.urls_crawled,
            endpoints_discovered=recon_summary.endpoints_discovered,
            forms_discovered=recon_summary.forms_discovered,
            technologies=recon_summary.technologies,
            severity_summary=severity_summary,
            findings=findings,
            attack_surface_summary=self.get_attack_surface_summary(),
            intelligence_summary=self._intelligence_summary,
            scan_plan=self._scan_plan,
            context_assessment=self._context_assessment,
            security_coverage=self._security_coverage,
            execution_reliability=self._execution_reliability,
            evidence_intelligence=self._evidence_intelligence,
        )

    def _build_cancelled_report(self) -> UnifiedScanReport:
        return UnifiedScanReport(
            scan_id=self.scan_id,
            target_url=self.target_url,
            profile=self.profile,
            status=ScanStatus.CANCELLED,
            created_at=self.created_at,
            started_at=self.started_at,
            completed_at=self.completed_at,
            duration_seconds=self.duration_seconds,
            urls_crawled=0,
            endpoints_discovered=0,
            forms_discovered=0,
            technologies=[],
            severity_summary=SeveritySummarySchema(),
            findings=[],
        )

    def _build_failure_report(self) -> UnifiedScanReport:
        return UnifiedScanReport(
            scan_id=self.scan_id,
            target_url=self.target_url,
            profile=self.profile,
            status=ScanStatus.FAILED,
            created_at=self.created_at,
            started_at=self.started_at,
            completed_at=self.completed_at,
            duration_seconds=self.duration_seconds,
            urls_crawled=0,
            endpoints_discovered=0,
            forms_discovered=0,
            technologies=[],
            severity_summary=SeveritySummarySchema(),
            findings=[],
        )


class ScanLifecycleRegistry:
    """Thread-safe in-memory registry managing scan jobs, active orchestrators, unified reports, and discovery engines."""

    DEFAULT_MAX_RETAINED_SCANS = 100

    def __init__(self, max_retained_scans: int = DEFAULT_MAX_RETAINED_SCANS):
        self.max_retained_scans = max(1, int(max_retained_scans))
        self._jobs: Dict[UUID, ScanJobResponse] = {}
        self._orchestrators: Dict[UUID, ScanOrchestrator] = {}
        self._reports: Dict[UUID, UnifiedScanReport] = {}
        self._discovery_engines: Dict[UUID, AttackSurfaceIntelligenceEngine] = {}
        self._standalone_findings: Dict[UUID, FindingResponse] = {}

    def _evict_scan(self, scan_id: UUID) -> None:
        self._jobs.pop(scan_id, None)
        self._orchestrators.pop(scan_id, None)
        self._reports.pop(scan_id, None)
        self._discovery_engines.pop(scan_id, None)
        stale_finding_ids = [
            fid for fid, finding in self._standalone_findings.items() if finding.scan_id == scan_id
        ]
        for fid in stale_finding_ids:
            self._standalone_findings.pop(fid, None)

    def _enforce_retention_bounds(self) -> None:
        """Evicts oldest completed/terminal scans once capacity exceeds max_retained_scans, never dropping RUNNING scans."""
        tracked_ids = list(dict.fromkeys(list(self._jobs.keys()) + list(self._reports.keys())))
        if len(tracked_ids) <= self.max_retained_scans:
            return

        excess = len(tracked_ids) - self.max_retained_scans
        for sid in tracked_ids:
            if excess <= 0:
                break
            orch = self._orchestrators.get(sid)
            job = self._jobs.get(sid)
            current_status = orch.status if orch else (job.status if job else ScanStatus.COMPLETED)
            if current_status == ScanStatus.RUNNING:
                continue
            self._evict_scan(sid)
            excess -= 1

    def register_job(self, job: ScanJobResponse) -> None:
        self._jobs[job.id] = job
        self._enforce_retention_bounds()

    def register_orchestrator(self, orchestrator: ScanOrchestrator) -> None:
        self._orchestrators[orchestrator.scan_id] = orchestrator
        self._jobs[orchestrator.scan_id] = orchestrator.get_job_response()
        if orchestrator.discovery_engine:
            self._discovery_engines[orchestrator.scan_id] = orchestrator.discovery_engine
        self._enforce_retention_bounds()

    def register_discovery_engine(self, scan_id: UUID, engine: AttackSurfaceIntelligenceEngine) -> None:
        self._discovery_engines[scan_id] = engine

    def get_discovery_engine(self, scan_id: UUID) -> Optional[AttackSurfaceIntelligenceEngine]:
        if scan_id in self._discovery_engines:
            return self._discovery_engines[scan_id]
        if scan_id in self._orchestrators and self._orchestrators[scan_id].discovery_engine:
            return self._orchestrators[scan_id].discovery_engine
        return None

    def get_job(self, scan_id: UUID) -> Optional[ScanJobResponse]:
        if scan_id in self._orchestrators:
            return self._orchestrators[scan_id].get_job_response()
        return self._jobs.get(scan_id)

    def list_jobs(self) -> List[ScanJobResponse]:
        results: List[ScanJobResponse] = []
        for scan_id, job in self._jobs.items():
            if scan_id in self._orchestrators:
                results.append(self._orchestrators[scan_id].get_job_response())
            else:
                results.append(job)
        return results

    def store_report(self, report: UnifiedScanReport) -> None:
        self._reports[report.scan_id] = report
        if report.scan_id in self._jobs:
            job = self._jobs[report.scan_id]
            job.status = report.status
            job.completed_at = report.completed_at
            job.duration_seconds = report.duration_seconds
            job.urls_crawled = report.urls_crawled
            job.findings_count = len(report.findings)
        self._enforce_retention_bounds()

    def get_report(self, scan_id: UUID) -> Optional[UnifiedScanReport]:
        if scan_id in self._reports:
            return self._reports[scan_id]
        if scan_id in self._orchestrators and self._orchestrators[scan_id]._report:
            return self._orchestrators[scan_id]._report
        return None

    def store_standalone_finding(self, finding: FindingResponse) -> None:
        self._standalone_findings[finding.id] = finding

    def get_findings(self, scan_id: UUID) -> List[FindingResponse]:
        report = self.get_report(scan_id)
        if report:
            return report.findings
        return [f for f in self._standalone_findings.values() if f.scan_id == scan_id]

    def get_all_findings(self) -> List[FindingResponse]:
        """Returns all findings across all tracked scan reports without duplicates across orchestrator/report stores."""
        seen_scans: Set[UUID] = set()
        seen_ids: Set[UUID] = set()
        results: List[FindingResponse] = []
        for scan_id, report in self._reports.items():
            seen_scans.add(scan_id)
            for f in report.findings:
                seen_ids.add(f.id)
                results.append(f)
        for scan_id, orch in self._orchestrators.items():
            if scan_id not in seen_scans and orch._report:
                for f in orch._report.findings:
                    seen_ids.add(f.id)
                    results.append(f)
        for f in self._standalone_findings.values():
            if f.id not in seen_ids:
                results.append(f)
        return results

    def get_finding_by_id(self, finding_id: UUID) -> Optional[Tuple[FindingResponse, Optional[UnifiedScanReport]]]:
        """Looks up a specific finding across all registered scans."""
        seen_scans: Set[UUID] = set()
        for scan_id, report in self._reports.items():
            seen_scans.add(scan_id)
            for f in report.findings:
                if f.id == finding_id:
                    return (f, report)
        for scan_id, orch in self._orchestrators.items():
            if scan_id not in seen_scans and orch._report:
                for f in orch._report.findings:
                    if f.id == finding_id:
                        return (f, orch._report)
        if finding_id in self._standalone_findings:
            return (self._standalone_findings[finding_id], None)
        return None

    def list_reports(self) -> List[UnifiedScanReport]:
        """Returns all unique scan reports stored across reports and orchestrators."""
        seen: Set[UUID] = set()
        results: List[UnifiedScanReport] = []
        for sid, rep in self._reports.items():
            seen.add(sid)
            results.append(rep)
        for sid, orch in self._orchestrators.items():
            if sid not in seen and orch._report:
                results.append(orch._report)
        return results

    def has_active_job(self, target_url: str, profile: ScanProfile) -> Optional[UUID]:
        """Detects whether an identical scan job is currently RUNNING or QUEUED."""
        norm = target_url.strip().rstrip("/").lower()
        for job in self.list_jobs():
            if (
                job.target_url
                and job.target_url.strip().rstrip("/").lower() == norm
                and job.profile == profile
                and job.status == ScanStatus.RUNNING
            ):
                return job.id
        return None

    def get_intelligence_summary(self, scan_id: UUID) -> Optional[ScanIntelligenceSummarySchema]:
        report = self.get_report(scan_id)
        if report and report.intelligence_summary:
            return report.intelligence_summary
        if scan_id in self._orchestrators and self._orchestrators[scan_id]._intelligence_summary:
            return self._orchestrators[scan_id]._intelligence_summary
        return None

    def update_scan_risk_config(self, scan_id: UUID, asset_criticality: float) -> Optional[ScanIntelligenceSummarySchema]:
        """Recalculates contextual risk for a completed scan using updated analyst asset criticality."""
        report = self.get_report(scan_id)
        if not report:
            return None
        if scan_id in self._orchestrators:
            self._orchestrators[scan_id].asset_criticality = asset_criticality
        disc_eng = self.get_discovery_engine(scan_id)
        updated_findings, risk_breakdown = VulnerabilityIntelligenceEngine.recalculate_risk_for_findings(
            findings=report.findings,
            asset_criticality=asset_criticality,
            discovery_engine=disc_eng,
        )
        report.findings = updated_findings
        if report.intelligence_summary:
            report.intelligence_summary.contextual_priority_breakdown = risk_breakdown
        return report.intelligence_summary

    def cancel_scan(self, scan_id: UUID) -> bool:
        if scan_id in self._orchestrators:
            self._orchestrators[scan_id].cancel()
            self._jobs[scan_id] = self._orchestrators[scan_id].get_job_response()
            return True
        if scan_id in self._jobs:
            self._jobs[scan_id].status = ScanStatus.CANCELLED
            return True
        return False

    def clear(self) -> None:
        """Clears all in-memory scan state (primarily for test cleanup)."""
        self._jobs.clear()
        self._orchestrators.clear()
        self._reports.clear()
        self._discovery_engines.clear()
        self._standalone_findings.clear()


# Global singleton registry instance
scan_registry = ScanLifecycleRegistry()
