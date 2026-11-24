import pytest
from unittest.mock import patch
import httpx

from backend.app.scanner.crawler.client import AsyncHTTPClient
from backend.app.scanner.reconnaissance.robots_sitemap import RobotsSitemapDiscovery
from backend.app.scanner.scope.scope_gate import ScopeGate


@pytest.mark.asyncio
async def test_robots_txt_parsing():
    base_url = "https://app.example.com"
    scope_gate = ScopeGate(target_base_url=base_url)

    robots_content = """
    User-agent: *
    Disallow: /admin/
    Disallow: /private/data
    Allow: /public/
    Sitemap: https://app.example.com/sitemap.xml
    Sitemap: https://external.com/sitemap.xml
    """

    async with AsyncHTTPClient(scope_gate=scope_gate) as client:
        mock_resp = httpx.Response(status_code=200, text=robots_content)
        with patch.object(client, "get", return_value=(mock_resp, None)):
            discovery = RobotsSitemapDiscovery(base_url, client, scope_gate)
            urls, sitemaps = await discovery.discover_robots()

            assert "https://app.example.com/admin/" in urls or "https://app.example.com/admin" in urls
            assert "https://app.example.com/private/data" in urls
            assert "https://app.example.com/sitemap.xml" in sitemaps
            assert "https://external.com/sitemap.xml" in sitemaps


@pytest.mark.asyncio
async def test_sitemap_xml_parsing():
    base_url = "https://app.example.com"
    scope_gate = ScopeGate(target_base_url=base_url)

    sitemap_xml = """<?xml version="1.0" encoding="UTF-8"?>
    <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
       <url>
          <loc>https://app.example.com/page1</loc>
          <lastmod>2026-11-24</lastmod>
       </url>
       <url>
          <loc>https://app.example.com/page2</loc>
       </url>
       <url>
          <loc>https://out-of-scope.com/page3</loc>
       </url>
    </urlset>
    """

    async with AsyncHTTPClient(scope_gate=scope_gate) as client:
        mock_resp = httpx.Response(status_code=200, text=sitemap_xml)
        with patch.object(client, "get", return_value=(mock_resp, None)):
            discovery = RobotsSitemapDiscovery(base_url, client, scope_gate)
            urls = await discovery.discover_sitemap("https://app.example.com/sitemap.xml")

            assert "https://app.example.com/page1" in urls
            assert "https://app.example.com/page2" in urls
            assert not any("out-of-scope.com" in u for u in urls)
