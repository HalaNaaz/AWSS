import pytest
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

from shared.schemas.common import Severity, FindingStatus
from backend.app.scanner.active.models import ActiveTarget, RequestBudgetTracker
from backend.app.scanner.active.analyzers.ssrf import SSRFAnalyzer


@pytest.fixture
def ssrf_analyzer():
    return SSRFAnalyzer()


@pytest.fixture
def mock_client():
    client = MagicMock()
    client.get = AsyncMock()
    return client


@pytest.mark.asyncio
async def test_ssrf_candidate_error_reflection(ssrf_analyzer, mock_client):
    target = ActiveTarget(
        url="https://app.local/proxy?url=https://example.com/api",
        method="GET",
        parameters={"url": "https://example.com/api"},
        baseline_status=200,
        baseline_body="<html>Remote content</html>",
    )

    # Server attempts fetch and exposes connection error
    err_resp = MagicMock(
        status_code=500,
        text="<html>Error in cURL: Could not resolve host: scan-probe.invalid</html>",
        headers={},
    )
    mock_client.get.return_value = (err_resp, None)

    budget = RequestBudgetTracker(budget=10)
    findings = await ssrf_analyzer.check(
        target=target,
        client=mock_client,
        budget=budget,
        scan_id=uuid4(),
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "ACT-SSRF-URL-PARAM"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].status == FindingStatus.SUSPECTED
    assert findings[0].parameter == "url"


@pytest.mark.asyncio
async def test_ssrf_non_url_param_ignored(ssrf_analyzer, mock_client):
    target = ActiveTarget(
        url="https://app.local/items?sort=asc&filter=new",
        method="GET",
        parameters={"sort": "asc", "filter": "new"},
        baseline_status=200,
        baseline_body="<html>Item List</html>",
    )

    budget = RequestBudgetTracker(budget=10)
    findings = await ssrf_analyzer.check(
        target=target,
        client=mock_client,
        budget=budget,
        scan_id=uuid4(),
    )

    assert len(findings) == 0
    # No network requests should have been made for non-URL parameters
    assert mock_client.get.call_count == 0
