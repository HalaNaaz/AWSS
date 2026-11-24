import pytest
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

from shared.schemas.common import Severity, FindingStatus
from backend.app.scanner.active.models import ActiveTarget, RequestBudgetTracker
from backend.app.scanner.active.analyzers.sqli import SQLInjectionAnalyzer


@pytest.fixture
def sqli_analyzer():
    return SQLInjectionAnalyzer()


@pytest.fixture
def mock_client():
    client = MagicMock()
    client.get = AsyncMock()
    return client


@pytest.mark.asyncio
async def test_sqli_syntax_error_probe_detection(sqli_analyzer, mock_client):
    target = ActiveTarget(
        url="https://app.local/products?cat=books",
        method="GET",
        parameters={"cat": "books"},
        baseline_status=200,
        baseline_body="<html>Books Catalogue</html>",
    )

    # Mock response to quote probe returning MySQL error
    err_resp = MagicMock(
        status_code=500,
        text="<html>Error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version</html>",
        headers={},
    )
    mock_client.get.return_value = (err_resp, None)

    budget = RequestBudgetTracker(budget=10)
    findings = await sqli_analyzer.check(
        target=target,
        client=mock_client,
        budget=budget,
        scan_id=uuid4(),
    )

    error_findings = [f for f in findings if f.rule_id == "ACT-SQLI-ERROR"]
    assert len(error_findings) == 1
    assert error_findings[0].severity == Severity.HIGH
    assert error_findings[0].status == FindingStatus.SUSPECTED
    assert error_findings[0].parameter == "cat"
    assert "MySQL" in error_findings[0].description


@pytest.mark.asyncio
async def test_sqli_boolean_invariant_two_phase_verification(sqli_analyzer, mock_client):
    target = ActiveTarget(
        url="https://app.local/user?id=101",
        method="GET",
        parameters={"id": "101"},
        baseline_status=200,
        baseline_body="<html>User Profile: Alice, Admin: False</html>",
    )

    # Mock responses:
    # 1. Syntax probe: no error
    syntax_resp = MagicMock(status_code=200, text="<html>User Profile: Alice</html>", headers={})
    # 2. True probe (' AND 8943=8943-- ): mirrors baseline length and status
    true_resp = MagicMock(status_code=200, text="<html>User Profile: Alice, Admin: False</html>", headers={})
    # 3. False probe (' AND 8943=8944-- ): returns empty/different body
    false_resp = MagicMock(status_code=200, text="<html>User Not Found</html>", headers={})

    mock_client.get.side_effect = [
        (syntax_resp, None),
        (true_resp, None),
        (false_resp, None),
    ]

    budget = RequestBudgetTracker(budget=10)
    findings = await sqli_analyzer.check(
        target=target,
        client=mock_client,
        budget=budget,
        scan_id=uuid4(),
    )

    verified_findings = [f for f in findings if f.rule_id == "ACT-SQLI-BOOLEAN"]
    assert len(verified_findings) == 1
    assert verified_findings[0].severity == Severity.CRITICAL
    assert verified_findings[0].status == FindingStatus.VERIFIED
    assert verified_findings[0].confidence == 0.98
    assert verified_findings[0].parameter == "id"


@pytest.mark.asyncio
async def test_sqli_non_vulnerable_endpoint(sqli_analyzer, mock_client):
    target = ActiveTarget(
        url="https://app.local/search?q=test",
        method="GET",
        parameters={"q": "test"},
        baseline_status=200,
        baseline_body="<html>Results for query</html>",
    )

    # When all probes return normal safe pages without error and without differential boolean behavior
    normal_resp = MagicMock(status_code=200, text="<html>Results for query</html>", headers={})
    mock_client.get.return_value = (normal_resp, None)

    budget = RequestBudgetTracker(budget=10)
    findings = await sqli_analyzer.check(
        target=target,
        client=mock_client,
        budget=budget,
        scan_id=uuid4(),
    )

    assert len(findings) == 0
