import pytest
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

from shared.schemas.common import Severity, FindingStatus
from backend.app.scanner.active.models import ActiveTarget, RequestBudgetTracker
from backend.app.scanner.active.analyzers.authentication import AuthenticationAnalyzer


@pytest.fixture
def auth_analyzer():
    return AuthenticationAnalyzer()


@pytest.fixture
def mock_client():
    client = MagicMock()
    client.get = AsyncMock()
    client.request = AsyncMock()
    return client


@pytest.mark.asyncio
async def test_auth_session_id_in_url(auth_analyzer, mock_client):
    target = ActiveTarget(
        url="https://app.local/dashboard?session_id=abc123secret",
        method="GET",
        parameters={"session_id": "abc123secret"},
        baseline_status=200,
        baseline_body="<html>Dashboard</html>",
    )

    budget = RequestBudgetTracker(budget=10)
    findings = await auth_analyzer.check(
        target=target,
        client=mock_client,
        budget=budget,
        scan_id=uuid4(),
    )

    url_findings = [f for f in findings if f.rule_id == "ACT-AUTH-SESSION-URL"]
    assert len(url_findings) == 1
    assert url_findings[0].severity == Severity.MEDIUM
    assert url_findings[0].status == FindingStatus.VERIFIED
    assert url_findings[0].parameter == "session_id"


@pytest.mark.asyncio
async def test_auth_cleartext_login_endpoint(auth_analyzer, mock_client):
    target = ActiveTarget(
        url="http://insecure.local/login",
        method="GET",
        baseline_status=200,
        baseline_body="<html>Login Form</html>",
    )
    mock_client.get.return_value = (MagicMock(headers={}), None)

    budget = RequestBudgetTracker(budget=10)
    findings = await auth_analyzer.check(
        target=target,
        client=mock_client,
        budget=budget,
        scan_id=uuid4(),
    )

    clear_findings = [f for f in findings if f.rule_id == "ACT-AUTH-CLEAR-TEXT-LOGIN"]
    assert len(clear_findings) == 1
    assert clear_findings[0].severity == Severity.HIGH
    assert clear_findings[0].status == FindingStatus.VERIFIED
