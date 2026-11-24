import pytest
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

from shared.schemas.common import Severity, FindingStatus
from backend.app.scanner.active.models import ActiveTarget, RequestBudgetTracker
from backend.app.scanner.active.analyzers.xss import XSSAnalyzer


@pytest.fixture
def xss_analyzer():
    return XSSAnalyzer()


@pytest.fixture
def mock_client():
    client = MagicMock()
    client.get = AsyncMock()
    return client


@pytest.mark.asyncio
async def test_xss_reflected_html_body_context(xss_analyzer, mock_client):
    target = ActiveTarget(
        url="https://app.local/search?q=alice",
        method="GET",
        parameters={"q": "alice"},
        baseline_status=200,
        baseline_body="<html><body><h1>Results for alice</h1></body></html>",
    )

    # Mock response where canary tag is reflected unescaped
    def mock_get(url):
        # Extract q parameter from url
        import urllib.parse
        parsed = urllib.parse.urlparse(url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        q_val = params.get("q", "")
        # Server naively reflects input directly into body
        return MagicMock(status_code=200, text=f"<html><body><h1>Results for {q_val}</h1></body></html>", headers={}), None

    mock_client.get.side_effect = mock_get

    budget = RequestBudgetTracker(budget=10)
    findings = await xss_analyzer.check(
        target=target,
        client=mock_client,
        budget=budget,
        scan_id=uuid4(),
    )

    html_findings = [f for f in findings if f.rule_id == "ACT-XSS-REFLECTED-HTML"]
    assert len(html_findings) == 1
    assert html_findings[0].severity == Severity.HIGH
    assert html_findings[0].status == FindingStatus.VERIFIED
    assert html_findings[0].parameter == "q"


@pytest.mark.asyncio
async def test_xss_escaped_reflection_is_safe(xss_analyzer, mock_client):
    target = ActiveTarget(
        url="https://app.local/search?q=alice",
        method="GET",
        parameters={"q": "alice"},
        baseline_status=200,
        baseline_body="<html><body><h1>Results for alice</h1></body></html>",
    )

    # Server properly uses html.escape
    def mock_safe_get(url):
        import html
        import urllib.parse
        parsed = urllib.parse.urlparse(url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        q_val = html.escape(params.get("q", ""))
        return MagicMock(status_code=200, text=f"<html><body><h1>Results for {q_val}</h1></body></html>", headers={}), None

    mock_client.get.side_effect = mock_safe_get

    budget = RequestBudgetTracker(budget=10)
    findings = await xss_analyzer.check(
        target=target,
        client=mock_client,
        budget=budget,
        scan_id=uuid4(),
    )

    assert len(findings) == 0


@pytest.mark.asyncio
async def test_xss_attribute_breakout(xss_analyzer, mock_client):
    target = ActiveTarget(
        url="https://app.local/profile?name=alice",
        method="GET",
        parameters={"name": "alice"},
        baseline_status=200,
        baseline_body='<html><input type="text" name="user" value="alice"></html>',
    )

    def mock_attr_get(url):
        import urllib.parse
        parsed = urllib.parse.urlparse(url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        val = params.get("name", "")
        # Server escapes < and > but fails to escape quotes inside attribute
        sanitized_val = val.replace("<", "&lt;").replace(">", "&gt;")
        return MagicMock(status_code=200, text=f'<html><input type="text" name="user" value="{sanitized_val}"></html>', headers={}), None

    mock_client.get.side_effect = mock_attr_get

    budget = RequestBudgetTracker(budget=10)
    findings = await xss_analyzer.check(
        target=target,
        client=mock_client,
        budget=budget,
        scan_id=uuid4(),
    )

    attr_findings = [f for f in findings if f.rule_id == "ACT-XSS-REFLECTED-ATTR"]
    assert len(attr_findings) == 1
    assert attr_findings[0].severity == Severity.HIGH
    assert attr_findings[0].status == FindingStatus.VERIFIED
