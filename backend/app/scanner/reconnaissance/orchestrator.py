import asyncio
import time
from typing import Optional, List, Dict, Tuple
from uuid import UUID, uuid4

from backend.app.core.config import settings
from backend.app.core.logging import logger
from backend.app.scanner.crawler.client import AsyncHTTPClient
from backend.app.scanner.crawler.crawler import AsyncCrawler
from backend.app.scanner.crawler.normalizer import URLNormalizer
from backend.app.scanner.fingerprinting.technologies import TechnologyFingerprinter
from backend.app.scanner.passive.engine import PassiveAnalysisEngine
from backend.app.scanner.passive.models import HTTPResponseContext, PassiveFinding
from backend.app.scanner.reconnaissance.js_analyzer import JavaScriptEndpointExtractor
from backend.app.scanner.reconnaissance.robots_sitemap import RobotsSitemapDiscovery
from backend.app.scanner.discovery.engine import AttackSurfaceIntelligenceEngine
from backend.app.scanner.scope.scope_gate import ScopeGate
from shared.schemas.common import ScopeRuleType
from shared.schemas.discovery import (
    DiscoveredEndpointCreate,
    FormMetadataSchema,
    TechnologyObservationSchema,
    ReconSummaryResponse,
    DiscoveryMethod,
    EndpointCategory
)


class ReconOrchestrator:
    """Master Orchestrator coordinating discovery, crawling, robots/sitemap parsing, and JS extraction."""

    def __init__(
        self,
        target_url: str,
        scan_id: Optional[UUID] = None,
        scope_rules: Optional[List[Tuple[ScopeRuleType, str]]] = None,
        max_depth: int = 3,
        max_urls: int = 500,
        concurrency: int = 5,
        rate_limit_rps: float = 10.0,
        analyze_javascript: bool = True,
        respect_robots: bool = True
    ):
        self.target_url = target_url
        self.scan_id = scan_id or uuid4()
        self.scope_rules = scope_rules or []
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.concurrency = concurrency
        self.rate_limit_rps = rate_limit_rps
        self.analyze_javascript = analyze_javascript
        self.respect_robots = respect_robots

        # Initialize ScopeGate
        self.scope_gate = ScopeGate(
            target_base_url=self.target_url,
            scope_rules=self.scope_rules,
            allow_private_ips=settings.ALLOW_PRIVATE_IPS
        )
        self.discovery_engine = AttackSurfaceIntelligenceEngine(
            target_base_url=self.target_url,
            scope_gate=self.scope_gate,
            scan_id=self.scan_id
        )
        self.crawler: Optional[AsyncCrawler] = None
        self.discovered_endpoints: List[DiscoveredEndpointCreate] = []
        self.discovered_forms: List[FormMetadataSchema] = []
        self._is_cancelled = False

    def cancel(self):
        """Cancels running reconnaissance."""
        self._is_cancelled = True
        if self.crawler:
            self.crawler.cancel()

    async def run(self) -> ReconSummaryResponse:
        """Executes full reconnaissance pipeline."""
        start_time = time.perf_counter()
        logger.info(f"[ReconOrchestrator] Starting reconnaissance for target: {self.target_url} [Scan: {self.scan_id}]")

        technologies: List[TechnologyObservationSchema] = []
        seed_urls: List[Tuple[str, DiscoveryMethod]] = []
        passive_engine = PassiveAnalysisEngine()
        all_passive_findings: List[PassiveFinding] = []

        async with AsyncHTTPClient(
            scope_gate=self.scope_gate,
            rate_limit_rps=self.rate_limit_rps,
            max_redirects=5
        ) as client:
            # Step 1: Initial Baseline Request & Technology Fingerprint & Passive Checks
            root_resp, err = await client.get(self.target_url)
            if root_resp:
                self.discovery_engine.ingest_crawled_page(
                    url=self.target_url,
                    status_code=root_resp.status_code,
                    content_type=root_resp.headers.get("content-type"),
                    response_size=len(root_resp.text) if root_resp.text else 0,
                    headers=dict(root_resp.headers),
                    body=root_resp.text
                )
                techs = TechnologyFingerprinter.fingerprint(
                    scan_id=self.scan_id,
                    headers=dict(root_resp.headers),
                    html_body=root_resp.text
                )
                technologies.extend(techs)

                # Passive security analysis on root page
                raw_hdrs = []
                if hasattr(root_resp.headers, "raw"):
                    for k, v in root_resp.headers.raw:
                        k_str = k.decode("latin1", errors="replace") if isinstance(k, bytes) else str(k)
                        v_str = v.decode("latin1", errors="replace") if isinstance(v, bytes) else str(v)
                        raw_hdrs.append((k_str, v_str))
                else:
                    raw_hdrs = [(k, v) for k, v in root_resp.headers.items()]

                root_ctx = HTTPResponseContext(
                    url=self.target_url,
                    status_code=root_resp.status_code,
                    headers=dict(root_resp.headers),
                    raw_headers=raw_hdrs,
                    body=root_resp.text if root_resp.text else None,
                    method="GET"
                )
                all_passive_findings.extend(passive_engine.analyze_response(root_ctx))

            # Step 2: Robots.txt & Sitemap Discovery
            if not self._is_cancelled:
                robots_discovery = RobotsSitemapDiscovery(
                    base_url=self.target_url,
                    client=client,
                    scope_gate=self.scope_gate
                )
                robots_urls, sitemap_links = await robots_discovery.discover_robots()
                for ru in robots_urls:
                    seed_urls.append((ru, DiscoveryMethod.ROBOTS_TXT))

                # If sitemaps discovered, parse them
                for sm_link in sitemap_links:
                    if self._is_cancelled or len(seed_urls) >= 100:
                        break
                    sm_urls = await robots_discovery.discover_sitemap(sm_link)
                    for su in sm_urls:
                        seed_urls.append((su, DiscoveryMethod.SITEMAP_XML))

            # Step 3: Run Bounded HTTP Crawler
            self.crawler = AsyncCrawler(
                target_base_url=self.target_url,
                client=client,
                scope_gate=self.scope_gate,
                max_depth=self.max_depth,
                max_urls=self.max_urls,
                concurrency=self.concurrency,
                scan_id=self.scan_id
            )
            endpoints, forms, script_urls = await self.crawler.crawl(seed_urls=seed_urls)
            self.discovered_endpoints = endpoints
            self.discovered_forms = forms

            # Ingest crawl endpoints and forms into discovery engine
            for ep in endpoints:
                self.discovery_engine.ingest_crawled_page(
                    url=ep.url,
                    status_code=ep.status_code,
                    content_type=ep.content_type,
                    response_size=ep.response_size,
                    source_url=ep.source_url,
                    crawl_depth=ep.crawl_depth
                )
            for fm in forms:
                self.discovery_engine.ingest_form(
                    action_url=fm.action,
                    method=fm.method,
                    fields=[f.model_dump() if hasattr(f, "model_dump") else dict(f) for f in fm.fields],
                    source_url=fm.source_url
                )

            # Step 4: Passive JavaScript Analysis
            if self.analyze_javascript and not self._is_cancelled:
                for js_url in list(script_urls)[:20]:  # Cap at top 20 scripts
                    if self._is_cancelled or len(endpoints) >= self.max_urls:
                        break
                    if self.scope_gate.validate_url_in_scope(js_url):
                        js_resp, _ = await client.get(js_url)
                        if js_resp and js_resp.status_code == 200 and js_resp.text:
                            # Ingest into attack surface intelligence
                            js_intel = self.discovery_engine.ingest_javascript(
                                js_content=js_resp.text,
                                js_url=js_url
                            )
                            candidate_apis = js_intel.endpoints or JavaScriptEndpointExtractor.extract_endpoints(
                                js_content=js_resp.text,
                                base_url=self.target_url,
                                scope_gate=self.scope_gate
                            )
                            for cand in candidate_apis:
                                if cand not in [e.url for e in endpoints]:
                                    endpoints.append(
                                        DiscoveredEndpointCreate(
                                            scan_id=self.scan_id,
                                            url=cand,
                                            normalized_url=cand,
                                            method="GET",
                                            source_url=js_url,
                                            discovery_method=DiscoveryMethod.JAVASCRIPT_AST,
                                            crawl_depth=1,
                                            endpoint_category=EndpointCategory.API
                                        )
                                    )

        # Step 5: Consolidate Passive Security Findings
        if self.crawler and self.crawler.passive_findings:
            all_passive_findings.extend(self.crawler.passive_findings)

        unique_findings_map = {}
        for pf in all_passive_findings:
            key = (pf.rule_id, pf.url, pf.parameter)
            if key not in unique_findings_map:
                unique_findings_map[key] = pf.to_finding_response(self.scan_id)
        final_findings = list(unique_findings_map.values())

        # Ingest findings into discovery engine
        for pf in final_findings:
            ep_url = pf.endpoint.url if pf.endpoint else ""
            self.discovery_engine.record_finding(pf.title, ep_url, pf.severity.value)

        # Step 6: Compute Summary Metrics
        elapsed_seconds = round(time.perf_counter() - start_time, 2)
        categories_breakdown: Dict[str, int] = {}
        for ep in endpoints:
            cat_name = ep.endpoint_category.value
            categories_breakdown[cat_name] = categories_breakdown.get(cat_name, 0) + 1

        summary = ReconSummaryResponse(
            scan_id=self.scan_id,
            target_url=self.target_url,
            status="CANCELLED" if self._is_cancelled else "COMPLETED",
            urls_crawled=len(endpoints),
            endpoints_discovered=len(endpoints),
            forms_discovered=len(forms),
            technologies_detected=len(technologies),
            crawl_depth_reached=self.max_depth,
            execution_time_seconds=elapsed_seconds,
            categories_breakdown=categories_breakdown,
            technologies=technologies,
            findings_count=len(final_findings),
            findings=final_findings
        )
        logger.info(f"[ReconOrchestrator] Recon completed in {elapsed_seconds}s. Discovered: {len(endpoints)} endpoints, {len(forms)} forms, {len(final_findings)} passive findings.")
        return summary
