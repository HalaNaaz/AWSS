import pytest
from uuid import uuid4
import httpx
from unittest.mock import patch

from backend.app.scanner.crawler.client import AsyncHTTPClient
from backend.app.scanner.crawler.crawler import AsyncCrawler
from backend.app.scanner.reconnaissance.orchestrator import ReconOrchestrator
from backend.app.scanner.scope.scope_gate import ScopeGate


@pytest.mark.asyncio
async def test_crawler_passive_analysis_pipeline():
    base_url = "https://app.example.com"
    scope_gate = ScopeGate(base_url, allow_private_ips=True)

    home_html = """
    <html>
      <head><title>App</title></head>
      <body>
        <a href="/about">About</a>
        <!-- TODO: deploy internal admin key -->
      </body>
    </html>
    """
    about_html = "<html><body><h1>About Us</h1></body></html>"

    responses = {
        "https://app.example.com": (
            200,
            {
                "Content-Type": "text/html",
                "Server": "Apache/2.4.41 (Ubuntu)",
                "Set-Cookie": "session_id=secret123; Path=/"
            },
            home_html
        ),
        "https://app.example.com/": (
            200,
            {
                "Content-Type": "text/html",
                "Server": "Apache/2.4.41 (Ubuntu)",
                "Set-Cookie": "session_id=secret123; Path=/"
            },
            home_html
        ),
        "https://app.example.com/about": (
            200,
            {
                "Content-Type": "text/html",
                "X-Powered-By": "PHP/7.4.3"
            },
            about_html
        )
    }

    async with AsyncHTTPClient(scope_gate=scope_gate) as client:
        async def mock_get(url, headers=None):
            clean = url.rstrip("/")
            if url in responses:
                status, hdrs, body = responses[url]
                return httpx.Response(status_code=status, headers=hdrs, text=body), None
            elif clean in responses:
                status, hdrs, body = responses[clean]
                return httpx.Response(status_code=status, headers=hdrs, text=body), None
            return httpx.Response(404, text="Not Found"), None

        with patch.object(client, "get", side_effect=mock_get):
            crawler = AsyncCrawler(
                target_base_url=base_url,
                client=client,
                scope_gate=scope_gate,
                max_depth=2,
                max_urls=10,
                enable_passive_analysis=True
            )
            endpoints, forms, scripts = await crawler.crawl()
            assert len(endpoints) == 2
            assert len(crawler.passive_findings) > 0
            rule_ids = [f.rule_id for f in crawler.passive_findings]
            assert "PASSIVE-INFO-SERVER-VERSION" in rule_ids
            assert "PASSIVE-COOKIE-SECURE-MISSING" in rule_ids
            assert "PASSIVE-INFO-FRAMEWORK-DISCLOSURE" in rule_ids
            assert "PASSIVE-HTML-SENSITIVE-COMMENT" in rule_ids


@pytest.mark.asyncio
async def test_recon_orchestrator_aggregates_passive_findings():
    base_url = "https://app.example.com"

    orchestrator = ReconOrchestrator(
        target_url=base_url,
        max_depth=1,
        max_urls=5,
        analyze_javascript=False,
        respect_robots=False
    )

    home_html = "<html><body><h1>Home</h1><!-- secret_admin_token --></body></html>"

    with patch.object(AsyncHTTPClient, "get") as mock_get:
        async def async_get_mock(url, headers=None):
            resp = httpx.Response(
                200,
                headers={
                    "Content-Type": "text/html",
                    "Server": "nginx/1.18.0",
                    "X-Debug-Token": "testtoken123"
                },
                text=home_html
            )
            return resp, None

        mock_get.side_effect = async_get_mock

        with patch.object(orchestrator.scope_gate, "allow_private_ips", True):
            with patch.object(orchestrator.scope_gate, "pre_flight_check", return_value="93.184.216.34"):
                with patch.object(orchestrator.scope_gate, "validate_url_in_scope", return_value=True):
                    summary = await orchestrator.run()
                    assert summary.status == "COMPLETED"
                    assert summary.findings_count > 0
                    assert len(summary.findings) == summary.findings_count
                    cwe_ids = [f.cwe_id for f in summary.findings]
                    assert "CWE-200" in cwe_ids or "CWE-215" in cwe_ids or "CWE-693" in cwe_ids
