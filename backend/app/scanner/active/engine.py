import asyncio
import time
import urllib.parse
from typing import List, Dict, Optional, Set, Any
from uuid import UUID, uuid4

from backend.app.core.logging import logger
from backend.app.scanner.active.base import BaseActiveAnalyzer
from backend.app.scanner.active.models import ActiveTarget, ActiveFinding, RequestBudgetTracker
from backend.app.scanner.active.registry import active_plugin_registry, ActivePluginRegistry
from backend.app.scanner.crawler.client import AsyncHTTPClient
from backend.app.scanner.scope.scope_gate import ScopeGate
from shared.schemas.common import ScanProfile
from shared.schemas.discovery import DiscoveredEndpointCreate


class ActiveDetectionEngine:
    """Master Coordinator and execution pipeline for Active Vulnerability Detection."""

    def __init__(
        self,
        registry: Optional[ActivePluginRegistry] = None,
        request_budget: int = 100,
        concurrency: int = 4,
        timeout_seconds: float = 15.0,
    ):
        self.registry = registry or active_plugin_registry
        self.request_budget = request_budget
        self.concurrency = concurrency
        self.timeout_seconds = timeout_seconds
        self._is_cancelled = False
        self._budget_tracker = RequestBudgetTracker(budget=request_budget)

    def cancel(self) -> None:
        """Cooperative cancellation flag."""
        self._is_cancelled = True

    @property
    def is_cancelled(self) -> bool:
        return self._is_cancelled

    @property
    def budget_tracker(self) -> RequestBudgetTracker:
        return self._budget_tracker

    @classmethod
    def endpoint_to_active_target(cls, endpoint: DiscoveredEndpointCreate) -> ActiveTarget:
        """Helper converting discovered endpoint into an ActiveTarget."""
        parsed = urllib.parse.urlparse(endpoint.url)
        params = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
        return ActiveTarget(
            url=endpoint.url,
            method=endpoint.method,
            parameters=params,
        )

    async def run(
        self,
        targets: List[ActiveTarget],
        client: AsyncHTTPClient,
        scan_id: UUID,
        profile: ScanProfile = ScanProfile.SAFE_ACTIVE,
        enabled_modules: Optional[Set[str]] = None,
    ) -> List[ActiveFinding]:
        """Executes active security detection over target endpoints."""
        start_time = time.perf_counter()
        analyzers = self.registry.get_analyzers_for_profile(profile, enabled_modules)

        if not analyzers:
            logger.info(f"[ActiveDetectionEngine] No active analyzers enabled for profile {profile.value}.")
            return []

        logger.info(
            f"[ActiveDetectionEngine] Starting active detection for scan {scan_id} "
            f"[Profile: {profile.value}, Targets: {len(targets)}, Analyzers: {len(analyzers)}, Budget: {self.request_budget}]"
        )

        all_findings: List[ActiveFinding] = []
        semaphore = asyncio.Semaphore(self.concurrency)

        # First, ensure targets have baseline information if missing
        for target in targets:
            if target.baseline_status is None and self._budget_tracker.can_request() and not self._is_cancelled:
                self._budget_tracker.consume(1)
                try:
                    resp, _ = await client.get(target.url)
                    if resp:
                        target.baseline_status = resp.status_code
                        target.baseline_body = resp.text or ""
                        target.baseline_headers = dict(resp.headers)
                        target.content_type = resp.headers.get("content-type", "")
                except Exception as exc:
                    logger.debug(f"[ActiveDetectionEngine] Baseline fetch failed for {target.url}: {exc}")

        async def _probe_target(target: ActiveTarget, analyzer: BaseActiveAnalyzer) -> List[ActiveFinding]:
            if self._is_cancelled or not self._budget_tracker.can_request():
                return []
            async with semaphore:
                try:
                    return await asyncio.wait_for(
                        analyzer.check(
                            target=target,
                            client=client,
                            budget=self._budget_tracker,
                            scan_id=scan_id,
                        ),
                        timeout=self.timeout_seconds,
                    )
                except asyncio.TimeoutError:
                    logger.warning(f"[ActiveDetectionEngine] Timeout in {analyzer.analyzer_id} on {target.url}")
                    return []
                except Exception as exc:
                    logger.error(f"[ActiveDetectionEngine] Error in {analyzer.analyzer_id} on {target.url}: {exc}")
                    return []

        tasks = []
        for target in targets:
            if self._is_cancelled or not self._budget_tracker.can_request():
                break
            for analyzer in analyzers:
                tasks.append(_probe_target(target, analyzer))

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for res in results:
                if isinstance(res, list):
                    all_findings.extend(res)

        # Deduplicate findings by (rule_id, url, parameter)
        unique_findings_map = {}
        for f in all_findings:
            key = (f.rule_id, f.url, f.parameter)
            if key not in unique_findings_map:
                unique_findings_map[key] = f

        deduped = list(unique_findings_map.values())
        elapsed = round(time.perf_counter() - start_time, 2)
        logger.info(
            f"[ActiveDetectionEngine] Finished active detection in {elapsed}s. "
            f"Probes sent: {self._budget_tracker.total_sent}, Findings: {len(deduped)}"
        )
        return deduped
