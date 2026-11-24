import asyncio
import time
from typing import Set, Dict, List, Optional, Tuple
from urllib.parse import urlparse
from uuid import uuid4

from backend.app.core.logging import logger
from backend.app.scanner.crawler.client import AsyncHTTPClient
from backend.app.scanner.crawler.normalizer import URLNormalizer
from backend.app.scanner.crawler.parser import HTMLParser
from backend.app.scanner.scope.scope_gate import ScopeGate
from shared.schemas.discovery import (
    DiscoveredEndpointCreate,
    EndpointCategory,
    DiscoveryMethod,
    FormMetadataSchema
)
from backend.app.scanner.passive.engine import PassiveAnalysisEngine
from backend.app.scanner.passive.models import HTTPResponseContext, PassiveFinding


class AsyncCrawler:
    """Bounded, scope-enforced asynchronous HTTP web crawler."""

    def __init__(
        self,
        target_base_url: str,
        client: AsyncHTTPClient,
        scope_gate: ScopeGate,
        max_depth: int = 3,
        max_urls: int = 500,
        concurrency: int = 5,
        scan_id = None,
        enable_passive_analysis: bool = True
    ):
        self.target_base_url = target_base_url
        self.client = client
        self.scope_gate = scope_gate
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.concurrency = concurrency
        self.scan_id = scan_id or uuid4()
        self.enable_passive_analysis = enable_passive_analysis

        self.passive_engine = PassiveAnalysisEngine() if enable_passive_analysis else None
        self.passive_findings: List[PassiveFinding] = []

        self.visited_urls: Set[str] = set()
        self.discovered_endpoints: Dict[str, DiscoveredEndpointCreate] = {}
        self.discovered_forms: List[FormMetadataSchema] = []
        self.discovered_scripts: Set[str] = set()
        self.crawl_queue: asyncio.Queue[Tuple[str, int, Optional[str], DiscoveryMethod]] = asyncio.Queue()
        self._is_cancelled = False

    def cancel(self):
        """Signals crawler to halt gracefully."""
        self._is_cancelled = True

    async def crawl(self, seed_urls: Optional[List[Tuple[str, DiscoveryMethod]]] = None) -> Tuple[
        List[DiscoveredEndpointCreate],
        List[FormMetadataSchema],
        Set[str]
    ]:
        """Executes bounded asynchronous crawling starting from seed URLs and root target."""
        # Seed initial queue
        norm_root = URLNormalizer.normalize_url(self.target_base_url)
        if norm_root and norm_root not in self.visited_urls:
            self.visited_urls.add(norm_root)
            await self.crawl_queue.put((norm_root, 0, None, DiscoveryMethod.CRAWLER))

        if seed_urls:
            for seed_url, method in seed_urls:
                norm_seed = URLNormalizer.normalize_url(seed_url)
                if norm_seed and norm_seed not in self.visited_urls and self.scope_gate.validate_url_in_scope(norm_seed):
                    self.visited_urls.add(norm_seed)
                    await self.crawl_queue.put((norm_seed, 1, norm_root, method))

        semaphore = asyncio.Semaphore(self.concurrency)

        async def worker():
            while not self._is_cancelled:
                try:
                    # Timeout after 2 seconds of inactivity on the queue
                    url, depth, source, method = await asyncio.wait_for(self.crawl_queue.get(), timeout=2.0)
                except asyncio.TimeoutError:
                    break
                except asyncio.CancelledError:
                    break

                try:
                    if len(self.discovered_endpoints) >= self.max_urls:
                        break

                    try:
                        async with semaphore:
                            await self._process_url(url, depth, source, method)
                    except Exception as err:
                        logger.error(f"[Crawler] Error processing URL {url}: {str(err)}")
                finally:
                    self.crawl_queue.task_done()

        # Run concurrent workers
        worker_tasks = [asyncio.create_task(worker()) for _ in range(self.concurrency)]
        await asyncio.gather(*worker_tasks, return_exceptions=True)

        return (
            list(self.discovered_endpoints.values()),
            self.discovered_forms,
            self.discovered_scripts
        )

    async def _process_url(self, url: str, depth: int, source: Optional[str], method: DiscoveryMethod):
        """Fetches and parses a single URL."""
        if URLNormalizer.is_destructive_url(url):
            logger.info(f"[Crawler] Skipping destructive URL: {url}")
            return

        start_time = time.perf_counter()
        resp, error = await self.client.get(url)
        response_time = (time.perf_counter() - start_time) * 1000

        status_code = resp.status_code if resp else None
        content_type = resp.headers.get("content-type") if resp else None
        response_size = len(resp.content) if resp else None

        category = URLNormalizer.classify_endpoint(url, content_type)
        query_params = URLNormalizer.extract_query_params(url)

        endpoint_record = DiscoveredEndpointCreate(
            scan_id=self.scan_id,
            url=url,
            normalized_url=url,
            method="GET",
            status_code=status_code,
            content_type=content_type,
            response_size=response_size,
            response_time_ms=round(response_time, 2),
            source_url=source,
            discovery_method=method,
            crawl_depth=depth,
            endpoint_category=category,
            query_params=query_params or None
        )
        self.discovered_endpoints[url] = endpoint_record

        # Passive Security Analysis on observed response
        if resp and self.passive_engine:
            raw_hdrs: List[Tuple[str, str]] = []
            if hasattr(resp.headers, "raw"):
                for k, v in resp.headers.raw:
                    k_str = k.decode("latin1", errors="replace") if isinstance(k, bytes) else str(k)
                    v_str = v.decode("latin1", errors="replace") if isinstance(v, bytes) else str(v)
                    raw_hdrs.append((k_str, v_str))
            else:
                raw_hdrs = [(k, v) for k, v in resp.headers.items()]

            ctx = HTTPResponseContext(
                url=url,
                status_code=resp.status_code,
                headers=dict(resp.headers),
                raw_headers=raw_hdrs,
                body=resp.text if resp.text else None,
                method="GET"
            )
            findings = self.passive_engine.analyze_response(ctx)
            self.passive_findings.extend(findings)

        # If page is HTML and we haven't reached max depth, extract links & forms
        if resp and resp.status_code == 200 and resp.text and category == EndpointCategory.PAGE:
            parsed = HTMLParser.parse(resp.text, url)

            # Store passive form metadata
            for form in parsed.get("forms", []):
                self.discovered_forms.append(form)

            # Collect scripts for JS analysis
            for script in parsed.get("scripts", []):
                self.discovered_scripts.add(script)

            # Enqueue internal links
            if depth < self.max_depth and not self._is_cancelled:
                for link in parsed.get("links", []):
                    if (
                        link not in self.visited_urls
                        and len(self.discovered_endpoints) < self.max_urls
                        and self.scope_gate.validate_url_in_scope(link)
                    ):
                        self.visited_urls.add(link)
                        await self.crawl_queue.put((link, depth + 1, url, DiscoveryMethod.CRAWLER))
