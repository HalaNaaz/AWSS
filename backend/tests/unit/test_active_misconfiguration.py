import pytest
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

from shared.schemas.common import Severity, FindingStatus
from backend.app.scanner.active.models import ActiveTarget, RequestBudgetTracker
from backend.app.scanner.active.analyzers.misconfiguration import MisconfigurationAnalyzer


@pytest.fixture
def misconfig_analyzer():
    return MisconfigurationAnalyzer()


@pytest.fixture
def mock_client():
    client = MagicMock()
    client.get = AsyncMock()
    client.request = AsyncMock()
    return client


@pytest.mark.asyncio
async def test_misconfig_directory_listing_detected(misconfig_analyzer, mock_client):
    target = ActiveTarget(
        url="https://app.local/uploads/",
        method="GET",
        baseline_status=200,
        baseline_body="<html><head><title>Index of /uploads</title></head><body><h1>Index of /uploads</h1></body></html>",
    )
    mock_client.request.return_value = (MagicMock(headers={"allow": "GET, POST"}), None)

    budget = RequestBudgetTracker(budget=10)
    findings = await misconfig_analyzer.check(
        target=target,
        client=mock_client,
        budget=budget,
        scan_id=uuid4(),
    )

    dir_findings = [f for f in findings if f.rule_id == "ACT-MISCONFIG-DIRLIST"]
    assert len(dir_findings) == 1
    assert dir_findings[0].severity == Severity.MEDIUM
    assert dir_findings[0].status == FindingStatus.VERIFIED


@pytest.mark.asyncio
async def test_misconfig_unsafe_trace_method_detected(misconfig_analyzer, mock_client):
    target = ActiveTarget(
        url="https://app.local/api",
        method="GET",
        baseline_status=200,
        baseline_body="<html>API Root</html>",
    )
    options_resp = MagicMock(headers={"allow": "GET, POST, OPTIONS, TRACE"})
    mock_client.request.return_value = (options_resp, None)

    budget = RequestBudgetTracker(budget=10)
    findings = await misconfig_analyzer.check(
        target=target,
        client=mock_client,
        budget=budget,
        scan_id=uuid4(),
    )

    trace_findings = [f for f in findings if f.rule_id == "ACT-MISCONFIG-UNSAFE-METHODS"]
    assert len(trace_findings) == 1
    assert trace_findings[0].severity == Severity.LOW
    assert trace_findings[0].status == FindingStatus.VERIFIED


@pytest.mark.asyncio
async def test_misconfig_exposed_diagnostic_actuator(misconfig_analyzer, mock_client):
    target = ActiveTarget(
        url="https://app.local/",
        method="GET",
        baseline_status=200,
        baseline_body="<html>Home</html>",
    )
    mock_client.request.return_value = (MagicMock(headers={"allow": "GET"}), None)

    # Mock /actuator/health returning 200 with status
    def mock_get(url):
        if "actuator/health" in url:
            return MagicMock(status_code=200, text='{"status":"UP","details":{"diskSpace":{"status":"UP"}}}', headers={}), None
        return MagicMock(status_code=404, text="Not Found", headers={}), None

    mock_client.get.side_effect = mock_get

    budget = RequestBudgetTracker(budget=20)
    findings = await misconfig_analyzer.check(
        target=target,
        client=mock_client,
        budget=budget,
        scan_id=uuid4(),
    )

    diag_findings = [f for f in findings if f.rule_id == "ACT-MISCONFIG-DIAGNOSTIC"]
    assert len(diag_findings) >= 1
    assert "Spring Boot Actuator Health" in diag_findings[0].title


@pytest.mark.asyncio
async def test_misconfig_open_redirect_detected(misconfig_analyzer, mock_client):
    target = ActiveTarget(
        url="https://app.local/login?redirect=dashboard",
        method="GET",
        parameters={"redirect": "dashboard"},
        baseline_status=200,
        baseline_body="<html>Login Form</html>",
    )
    # Server accepts redirect without validation
    redirect_resp = MagicMock(
        status_code=302,
        headers={"location": "https://example.org/ashlynx_safe_test"},
        text="",
    )

    async def mock_request_impl(method, url, *args, **kwargs):
        if method == "OPTIONS":
            return MagicMock(headers={"allow": "GET"}), None
        return redirect_resp, None

    mock_client.request.side_effect = mock_request_impl
    mock_client.get.return_value = (redirect_resp, None)

    budget = RequestBudgetTracker(budget=10)
    findings = await misconfig_analyzer.check(
        target=target,
        client=mock_client,
        budget=budget,
        scan_id=uuid4(),
    )

    open_redirect = [f for f in findings if f.rule_id == "ACT-MISCONFIG-OPEN-REDIRECT"]
    assert len(open_redirect) == 1
    assert open_redirect[0].severity == Severity.MEDIUM
    assert open_redirect[0].status == FindingStatus.VERIFIED
