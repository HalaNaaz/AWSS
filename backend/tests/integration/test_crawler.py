import pytest
from uuid import uuid4
import httpx
from unittest.mock import patch

from backend.app.scanner.crawler.client import AsyncHTTPClient
from backend.app.scanner.crawler.crawler import AsyncCrawler
from backend.app.scanner.scope.scope_gate import ScopeGate
from shared.schemas.discovery import EndpointCategory, DiscoveryMethod


@pytest.mark.asyncio
async def test_crawler_multi_page_and_limits():
    target_url = "https://app.example.com"
    scan_id = uuid4()
    scope_gate = ScopeGate(target_base_url=target_url)

    # Mock responses for multi-page crawl
    html_home = """
    <html>
      <body>
        <a href="/about">About</a>
        <a href="/products">Products</a>
        <a href="https://external.com/out-of-scope">Out of Scope</a>
      </body>
    </html>
    """
    html_about = "<html><body><a href='/contact'>Contact</a></body></html>"
    html_products = "<html><body><p>Product list</p></body></html>"
    html_contact = "<html><body><a href='/about'>About</a></body></html>"

    responses = {
        "https://app.example.com": (200, "text/html", html_home),
        "https://app.example.com/": (200, "text/html", html_home),
        "https://app.example.com/about": (200, "text/html", html_about),
        "https://app.example.com/products": (200, "text/html", html_products),
        "https://app.example.com/contact": (200, "text/html", html_contact),
    }

    async with AsyncHTTPClient(scope_gate=scope_gate) as client:
        # Patch client.get to return local mock responses safely
        async def mock_get(url, headers=None):
            clean_url = url.rstrip("/")
            if url in responses:
                status, ct, body = responses[url]
                mock_resp = httpx.Response(status_code=status, headers={"content-type": ct}, text=body)
                return mock_resp, None
            elif clean_url in responses:
                status, ct, body = responses[clean_url]
                mock_resp = httpx.Response(status_code=status, headers={"content-type": ct}, text=body)
                return mock_resp, None
            return httpx.Response(status_code=404, text="Not Found"), None

        with patch.object(client, "get", side_effect=mock_get):
            crawler = AsyncCrawler(
                target_base_url=target_url,
                client=client,
                scope_gate=scope_gate,
                max_depth=2,
                max_urls=10,
                concurrency=2,
                scan_id=scan_id
            )
            endpoints, forms, scripts = await crawler.crawl()

            discovered_urls = {e.url.rstrip("/") for e in endpoints}
            assert "https://app.example.com" in discovered_urls
            assert "https://app.example.com/about" in discovered_urls
            assert "https://app.example.com/products" in discovered_urls
            # Out of scope link must NOT be discovered
            assert not any("external.com" in u for u in discovered_urls)
