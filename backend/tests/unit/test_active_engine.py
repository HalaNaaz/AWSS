import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

from shared.schemas.common import ScanProfile, Severity, FindingStatus
from backend.app.scanner.active.models import ActiveTarget, ActiveFinding, RequestBudgetTracker
from backend.app.scanner.active.base import BaseActiveAnalyzer
from backend.app.scanner.active.registry import ActivePluginRegistry
from backend.app.scanner.active.engine import ActiveDetectionEngine


class DummyActiveAnalyzer(BaseActiveAnalyzer):
    @property
    def analyzer_id(self) -> str:
        return "ACT-DUMMY-ANALYZER"

    @property
    def analyzer_name(self) -> str:
        return "Dummy Test Analyzer"

    @property
    def category(self) -> str:
        return "Testing"

    @property
    def supported_rules(self) -> List[str]:
        return ["ACT-DUMMY-01"]

    async def check(self, target: ActiveTarget, client, budget: RequestBudgetTracker, scan_id: uuid4):
        budget.consume(1)
        return [
            ActiveFinding(
                rule_id="ACT-DUMMY-01",
                title="Dummy Test Finding",
                description="Dummy finding description",
                cwe_id="CWE-20",
                owasp_category="A03:2021",
                severity=Severity.LOW,
                cvss_score=3.0,
                status=FindingStatus.VERIFIED,
                confidence=0.9,
                url=target.url,
                remediation="Fix dummy defect",
                detection_module=self.analyzer_id,
            )
        ]


def test_request_budget_tracker():
    budget = RequestBudgetTracker(budget=5)
    assert budget.remaining == 5
    assert budget.total_sent == 0
    assert budget.can_request() is True

    assert budget.consume(3) is True
    assert budget.remaining == 2
    assert budget.total_sent == 3

    assert budget.consume(3) is False  # Cannot over-consume
    assert budget.consume(2) is True
    assert budget.remaining == 0
    assert budget.can_request() is False


def test_active_plugin_registry():
    registry = ActivePluginRegistry()
    analyzers = registry.list_analyzers()
    assert len(analyzers) == 8

    rule_ids = registry.list_all_rules()
    assert "ACT-SQLI-ERROR" in rule_ids
    assert "ACT-XSS-REFLECTED-HTML" in rule_ids
    assert "ACT-MISCONFIG-DIRLIST" in rule_ids
    assert "ACT-SSRF-URL-PARAM" in rule_ids
    assert "ACT-XXE-ENTITY-EXPANSION" in rule_ids
    assert "ACT-AUTH-SESSION-URL" in rule_ids
    assert "ACT-TRAVERSAL-LFI" in rule_ids
    assert "ACT-API-GRAPHQL-INTROSPECTION" in rule_ids

    # Profile filtering
    passive_analyzers = registry.get_analyzers_for_profile(ScanProfile.PASSIVE_DISCOVERY)
    assert len(passive_analyzers) == 0

    safe_analyzers = registry.get_analyzers_for_profile(ScanProfile.SAFE_ACTIVE)
    assert len(safe_analyzers) >= 5

    standard_analyzers = registry.get_analyzers_for_profile(ScanProfile.STANDARD_ACTIVE)
    assert len(standard_analyzers) == 8


@pytest.mark.asyncio
async def test_active_detection_engine_execution():
    custom_registry = ActivePluginRegistry(analyzers=[DummyActiveAnalyzer()])
    engine = ActiveDetectionEngine(registry=custom_registry, request_budget=10)

    target = ActiveTarget(url="https://example.com/test", method="GET", parameters={"id": "1"})
    mock_client = MagicMock()
    mock_client.get = AsyncMock(return_value=(MagicMock(status_code=200, text="OK", headers={}), None))

    findings = await engine.run(
        targets=[target],
        client=mock_client,
        scan_id=uuid4(),
        profile=ScanProfile.SAFE_ACTIVE,
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "ACT-DUMMY-01"
    assert engine.budget_tracker.total_sent >= 1


@pytest.mark.asyncio
async def test_active_detection_engine_cancellation():
    custom_registry = ActivePluginRegistry(analyzers=[DummyActiveAnalyzer()])
    engine = ActiveDetectionEngine(registry=custom_registry, request_budget=10)
    engine.cancel()
    assert engine.is_cancelled is True

    target = ActiveTarget(url="https://example.com/test", method="GET")
    mock_client = MagicMock()

    findings = await engine.run(
        targets=[target],
        client=mock_client,
        scan_id=uuid4(),
        profile=ScanProfile.SAFE_ACTIVE,
    )

    assert len(findings) == 0


@pytest.mark.asyncio
async def test_misconfiguration_analyzer_empty_and_malformed_responses():
    from backend.app.scanner.active.analyzers.misconfiguration import MisconfigurationAnalyzer

    analyzer = MisconfigurationAnalyzer()
    budget = RequestBudgetTracker(budget=10)
    mock_client = MagicMock()
    mock_client.request = AsyncMock(return_value=(MagicMock(status_code=200, headers=None, text=""), None))
    mock_client.get = AsyncMock(return_value=(None, "timeout"))

    malformed_target = ActiveTarget(url="/relative-only", method="GET")
    assert await analyzer.check(malformed_target, mock_client, budget, uuid4()) == []

    empty_resp_target = ActiveTarget(url="https://example.com/", method="GET", baseline_body="", parameters={"next": "/home"})
    findings = await analyzer.check(empty_resp_target, mock_client, budget, uuid4())
    assert findings == []


@pytest.mark.asyncio
async def test_sqli_analyzer_empty_response_and_parameter_fallback():
    from backend.app.scanner.active.analyzers.sqli import SQLInjectionAnalyzer

    analyzer = SQLInjectionAnalyzer()
    budget = RequestBudgetTracker(budget=10)
    mock_client = MagicMock()
    mock_client.get = AsyncMock(return_value=(MagicMock(status_code=500, text=None), None))

    target_no_query = ActiveTarget(
        url="https://example.com/search",
        method="GET",
        parameters={"q": "books"},
        baseline_body="OK",
        baseline_status=200,
    )
    findings = await analyzer.check(target_no_query, mock_client, budget, uuid4())
    assert findings == []
    assert budget.total_sent >= 1
    assert "q=books" in mock_client.get.call_args_list[0][0][0]
