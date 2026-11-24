import asyncio
from datetime import datetime, timezone
import time
from typing import Optional, List, Dict, Tuple, Any
from uuid import UUID, uuid4

from backend.app.core.logging import logger
from backend.app.scanner.reconnaissance.orchestrator import ReconOrchestrator
from shared.schemas.common import ScanProfile, ScanStatus, ScopeRuleType
from shared.schemas.discovery import ReconSummaryResponse
from shared.schemas.finding import FindingResponse
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
    ):
        self.target_url = target_url.strip()
        self.scan_id = scan_id or uuid4()
        self.target_id = target_id
        self.profile = profile
        self.scope_rules = scope_rules or []
        self.respect_robots = respect_robots
        self.analyze_javascript = analyze_javascript

        # Resolve limits from presets with explicit override precedence
        preset = SCAN_PROFILE_PRESETS.get(profile, SCAN_PROFILE_PRESETS[ScanProfile.QUICK_ASSESSMENT])
        self.max_crawl_depth = max_crawl_depth if max_crawl_depth is not None else preset["max_crawl_depth"]
        self.max_urls = max_urls if max_urls is not None else preset["max_urls"]
        self.concurrency = concurrency if concurrency is not None else preset["concurrency"]
        self.rate_limit_rps = rate_limit_rps if rate_limit_rps is not None else preset["rate_limit_rps"]

        # Lifecycle tracking
        self.status: ScanStatus = ScanStatus.QUEUED
        self.created_at: datetime = datetime.now(timezone.utc)
        self.started_at: Optional[datetime] = None
        self.completed_at: Optional[datetime] = None
        self.duration_seconds: float = 0.0
        self.error_message: Optional[str] = None

        self._recon_orchestrator: Optional[ReconOrchestrator] = None
        self._recon_summary: Optional[ReconSummaryResponse] = None
        self._report: Optional[UnifiedScanReport] = None
        self._is_cancelled = False

    def cancel(self) -> None:
        """Triggers cooperative cancellation of the running scan."""
        logger.info(f"[ScanOrchestrator] Cancellation requested for scan {self.scan_id}")
        self._is_cancelled = True
        self.status = ScanStatus.CANCELLED
        if self._recon_orchestrator:
            self._recon_orchestrator.cancel()

    @property
    def is_cancelled(self) -> bool:
        return self._is_cancelled

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

            # Check cancellation before launching
            if self._is_cancelled:
                self.status = ScanStatus.CANCELLED
                self.completed_at = datetime.now(timezone.utc)
                self.duration_seconds = round(time.perf_counter() - start_time, 2)
                return self._build_cancelled_report()

            recon_summary = await self._recon_orchestrator.run()
            self._recon_summary = recon_summary

            self.duration_seconds = round(time.perf_counter() - start_time, 2)
            self.completed_at = datetime.now(timezone.utc)

            # Check if cancelled during crawl
            if self._is_cancelled or recon_summary.status == "CANCELLED":
                self.status = ScanStatus.CANCELLED
                report = self._build_report_from_summary(recon_summary, ScanStatus.CANCELLED)
            else:
                self.status = ScanStatus.COMPLETED
                report = self._build_report_from_summary(recon_summary, ScanStatus.COMPLETED)

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
    """Thread-safe in-memory registry managing scan jobs, active orchestrators, and unified reports."""

    def __init__(self):
        self._jobs: Dict[UUID, ScanJobResponse] = {}
        self._orchestrators: Dict[UUID, ScanOrchestrator] = {}
        self._reports: Dict[UUID, UnifiedScanReport] = {}

    def register_job(self, job: ScanJobResponse) -> None:
        self._jobs[job.id] = job

    def register_orchestrator(self, orchestrator: ScanOrchestrator) -> None:
        self._orchestrators[orchestrator.scan_id] = orchestrator
        self._jobs[orchestrator.scan_id] = orchestrator.get_job_response()

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

    def get_report(self, scan_id: UUID) -> Optional[UnifiedScanReport]:
        if scan_id in self._reports:
            return self._reports[scan_id]
        if scan_id in self._orchestrators and self._orchestrators[scan_id]._report:
            return self._orchestrators[scan_id]._report
        return None

    def get_findings(self, scan_id: UUID) -> List[FindingResponse]:
        report = self.get_report(scan_id)
        if report:
            return report.findings
        return []

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


# Global singleton registry instance
scan_registry = ScanLifecycleRegistry()
