import pytest
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

from shared.schemas.common import Severity, FindingStatus
from backend.app.scanner.active.models import ActiveTarget, RequestBudgetTracker
from backend.app.scanner.active.analyzers.xxe import XXEAnalyzer


@pytest.fixture
def xxe_analyzer():
    return XXEAnalyzer()


@pytest.fixture
def mock_client():
    client = MagicMock()
    client.request = AsyncMock()
    return client


@pytest.mark.asyncio
async def test_xxe_entity_expansion_detected(xxe_analyzer, mock_client):
    target = ActiveTarget(
        url="https://app.local/api/xml-parser",
        method="POST",
        content_type="application/xml",
        baseline_status=200,
        baseline_body="<response><status>OK</status></response>",
    )

    # Server reflects expanded entity
    resp = MagicMock(
        status_code=200,
        text=f"<response><received>{XXEAnalyzer.BENIGN_CANARY}</received></response>",
        headers={},
    )
    mock_client.request.return_value = (resp, None)

    budget = RequestBudgetTracker(budget=10)
    findings = await xxe_analyzer.check(
        target=target,
        client=mock_client,
        budget=budget,
        scan_id=uuid4(),
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "ACT-XXE-ENTITY-EXPANSION"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].status == FindingStatus.VERIFIED
    assert findings[0].confidence == 0.95


@pytest.mark.asyncio
async def test_xxe_hardened_parser_zero_findings(xxe_analyzer, mock_client):
    target = ActiveTarget(
        url="https://app.local/api/xml-parser",
        method="POST",
        content_type="application/xml",
    )

    # Hardened server rejects DTD or does not expand entity
    resp = MagicMock(
        status_code=400,
        text="<error>DOCTYPE declarations are prohibited</error>",
        headers={},
    )
    mock_client.request.return_value = (resp, None)

    budget = RequestBudgetTracker(budget=10)
    findings = await xxe_analyzer.check(
        target=target,
        client=mock_client,
        budget=budget,
        scan_id=uuid4(),
    )

    assert len(findings) == 0
