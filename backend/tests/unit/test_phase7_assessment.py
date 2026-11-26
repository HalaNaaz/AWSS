import base64
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from backend.app.scanner.active.analyzers.api_security import APISecurityAnalyzer
from backend.app.scanner.active.analyzers.traversal import PathTraversalAnalyzer
from backend.app.scanner.active.models import ActiveTarget, RequestBudgetTracker
from backend.app.scanner.active.registry import ActivePluginRegistry
from backend.app.scanner.discovery.engine import AttackSurfaceIntelligenceEngine
from backend.app.scanner.intelligence.coverage import SecurityCoverageEngine
from backend.app.scanner.intelligence.engine import VulnerabilityIntelligenceEngine
from backend.app.scanner.intelligence.normalizer import FindingNormalizer
from backend.app.scanner.intelligence.planner import IntelligentScanPlanner
from backend.app.scanner.passive.analyzers.cache_control import CacheControlAnalyzer
from backend.app.scanner.passive.analyzers.client_side import ClientSideSecurityAnalyzer
from backend.app.scanner.passive.analyzers.token_security import TokenSecurityAnalyzer
from backend.app.scanner.passive.engine import PassiveAnalysisEngine
from backend.app.scanner.passive.models import HTTPResponseContext
from backend.app.scanner.scope.scope_gate import ScopeGate
from shared.schemas.common import FindingStatus, ScanProfile, ScopeRuleType


def _make_jwt(header: dict, payload: dict) -> str:
    def enc(obj: dict) -> str:
        raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    return f"{enc(header)}.{enc(payload)}.sig123"


def test_cache_control_analyzer_detects_missing_no_store_and_public():
    analyzer = CacheControlAnalyzer()
    ctx = HTTPResponseContext(
        url="https://app.example.com/api/profile",
        status_code=200,
        headers={"Cache-Control": "public, max-age=60"},
    )
    findings = analyzer.analyze(ctx)
    rule_ids = {f.rule_id for f in findings}
    assert "PASSIVE-CACHE-SHARED-PUBLIC" in rule_ids
    assert "PASSIVE-CACHE-SENSITIVE-NO-STORE" in rule_ids


def test_cache_control_analyzer_ignores_non_sensitive_and_properly_configured():
    analyzer = CacheControlAnalyzer()
    non_sens = HTTPResponseContext(url="https://app.example.com/static/logo.png", status_code=200, headers={})
    assert analyzer.analyze(non_sens) == []

    good = HTTPResponseContext(
        url="https://app.example.com/api/profile",
        status_code=200,
        headers={"Cache-Control": "no-store, no-cache, private", "Pragma": "no-cache"},
    )
    assert analyzer.analyze(good) == []


def test_token_security_analyzer_detects_alg_none_weak_claims_and_query_token():
    analyzer = TokenSecurityAnalyzer()
    jwt_bad = _make_jwt({"alg": "none", "typ": "JWT"}, {"sub": "user1", "password": "secret"})
    ctx = HTTPResponseContext(
        url="https://app.example.com/auth/session",
        status_code=200,
        headers={"Authorization": f"Bearer {jwt_bad}"},
        body='<a href="/callback?access_token=abc123456">Continue</a>',
    )
    findings = analyzer.analyze(ctx)
    rule_ids = {f.rule_id for f in findings}
    assert "PASSIVE-JWT-ALG-NONE" in rule_ids
    assert "PASSIVE-JWT-WEAK-CLAIMS" in rule_ids
    assert "PASSIVE-AUTH-BEARER-QUERY" in rule_ids
    for f in findings:
        assert "secret" not in f.evidence_response
        assert "abc123456" not in f.evidence_response


def test_client_side_security_analyzer_detects_dom_tabnabbing_postmessage_and_mixed():
    analyzer = ClientSideSecurityAnalyzer()
    html = """
    <html><body>
      <a href="https://external.example/docs" target="_blank">External</a>
      <script src="http://cdn.insecure.example/lib.js"></script>
      <script>
        const q = location.search;
        document.getElementById('out').innerHTML = q;
        window.parent.postMessage({ok: true}, '*');
      </script>
    </body></html>
    """
    ctx = HTTPResponseContext(
        url="https://app.example.com/dashboard",
        status_code=200,
        headers={"Content-Type": "text/html"},
        body=html,
    )
    findings = analyzer.analyze(ctx)
    rule_ids = {f.rule_id for f in findings}
    assert "PASSIVE-CLIENT-TABNABBING" in rule_ids
    assert "PASSIVE-CLIENT-DOM-SINK" in rule_ids
    assert "PASSIVE-CLIENT-POSTMESSAGE-WILDCARD" in rule_ids
    assert "PASSIVE-CLIENT-MIXED-CONTENT" in rule_ids


@pytest.mark.asyncio
async def test_path_traversal_analyzer_two_phase_verification_and_fp_suppression():
    analyzer = PathTraversalAnalyzer()
    scan_id = uuid4()

    # Case 1: Genuine Unix /etc/passwd leak absent from negative control
    client_vuln = MagicMock()

    async def get_vuln(url, **kwargs):
        if "ashlynx_nonexistent" in url:
            return SimpleNamespace(status_code=404, text="File not found")
        if "etc%2Fpasswd" in url or "etc/passwd" in url:
            return SimpleNamespace(status_code=200, text="root:x:0:0:root:/root:/bin/bash\n")
        return SimpleNamespace(status_code=404, text="Not found")

    client_vuln.get = AsyncMock(side_effect=get_vuln)
    target = ActiveTarget(
        url="http://example.local/download?file=report.pdf",
        method="GET",
        parameters={"file": "report.pdf"},
        baseline_body="PDF content",
    )
    findings = await analyzer.check(target, client_vuln, RequestBudgetTracker(budget=10), scan_id)
    assert len(findings) == 1
    assert findings[0].rule_id == "ACT-TRAVERSAL-LFI"
    assert findings[0].status == FindingStatus.VERIFIED

    # Case 2: Static error page returning error text even on negative control -> suppressed
    client_fp = MagicMock()
    client_fp.get = AsyncMock(return_value=SimpleNamespace(status_code=200, text="No such file or directory"))
    fp_findings = await analyzer.check(target, client_fp, RequestBudgetTracker(budget=10), scan_id)
    assert fp_findings == []


@pytest.mark.asyncio
async def test_api_security_analyzer_detects_graphql_swagger_and_method_override():
    analyzer = APISecurityAnalyzer()
    scan_id = uuid4()

    client = MagicMock()

    async def mock_get(url, headers=None, **kwargs):
        if url.endswith("/openapi.json"):
            return SimpleNamespace(status_code=200, text='{"openapi":"3.0.0","paths":{"/users":{}}}')
        if headers and headers.get("X-HTTP-Method-Override") == "HEAD":
            return SimpleNamespace(status_code=200, text="")
        return SimpleNamespace(status_code=404, text="")

    async def mock_post(url, json=None, content=None, headers=None, **kwargs):
        if "graphql" in url:
            return SimpleNamespace(status_code=200, text='{"data":{"__schema":{"types":[{"name":"Query"}]}}}')
        return SimpleNamespace(status_code=415, text="")

    client.get = AsyncMock(side_effect=mock_get)
    client.post = AsyncMock(side_effect=mock_post)

    target = ActiveTarget(
        url="http://example.local/",
        method="GET",
        baseline_body="<html><body>Home Page Content Here</body></html>",
    )
    findings = await analyzer.check(target, client, RequestBudgetTracker(budget=20), scan_id)
    rule_ids = {f.rule_id for f in findings}
    assert "ACT-API-GRAPHQL-INTROSPECTION" in rule_ids
    assert "ACT-API-SWAGGER-EXPOSED" in rule_ids
    assert "ACT-API-METHOD-OVERRIDE" in rule_ids


def test_phase7_registry_planner_coverage_and_avive_integration():
    passive_engine = PassiveAnalysisEngine()
    passive_ids = {a["analyzer_id"] for a in passive_engine.list_analyzers()}
    assert {"SEC-CACHE-ANALYZER", "AUTH-TOKEN-ANALYZER", "CLIENT-SEC-ANALYZER"}.issubset(passive_ids)

    active_reg = ActivePluginRegistry()
    active_ids = {a["analyzer_id"] for a in active_reg.list_analyzers()}
    assert {"ACT-TRAVERSAL-ANALYZER", "ACT-API-SEC-ANALYZER"}.issubset(active_ids)

    # ScopeGate production SSRF invariant remains enforced
    prod_gate = ScopeGate(
        target_base_url="https://example.com/",
        scope_rules=[(ScopeRuleType.INCLUDE, "https://example.com/*")],
        allow_private_ips=False,
    )
    assert prod_gate.validate_url_in_scope("http://127.0.0.1:8089/") is False

    # Discovery + Planner integration
    scan_id = uuid4()
    discovery = AttackSurfaceIntelligenceEngine(
        target_base_url="https://example.com/",
        scope_gate=prod_gate,
        scan_id=scan_id,
    )
    discovery.ingest_crawled_page(
        url="https://example.com/api/download?file=doc.txt",
        status_code=200,
        content_type="application/json",
        headers={"Content-Type": "application/json"},
        body='{"ok": true}',
        crawl_depth=0,
    )
    plan = IntelligentScanPlanner.build_plan(
        scan_id=scan_id,
        target_url="https://example.com/",
        profile=ScanProfile.STANDARD_ACTIVE,
        scope_gate=prod_gate,
        discovery_engine=discovery,
        registry=active_reg,
    )
    planned_analyzers = {a for c in plan.planned_checks for a in c.selected_analyzers}
    assert "ACT-TRAVERSAL-ANALYZER" in planned_analyzers
    assert "ACT-API-SEC-ANALYZER" in planned_analyzers

    # AVIVE normalization + remediation + coverage
    raw_finding = CacheControlAnalyzer().analyze(
        HTTPResponseContext(url="https://example.com/api/download?file=doc.txt", status_code=200, headers={})
    )[0].to_finding_response(scan_id)
    assert FindingNormalizer.normalize_cwe(raw_finding.cwe_id) == "CWE-525"

    enriched, summary = VulnerabilityIntelligenceEngine.process_findings(
        raw_findings=[raw_finding],
        scan_id=scan_id,
        discovery_engine=discovery,
    )
    assert len(enriched) == 1
    assert enriched[0].intelligence is not None
    assert enriched[0].intelligence.vulnerability_category == "CACHE_SECURITY"
    assert summary.total_raw_findings == 1

    cov = SecurityCoverageEngine.evaluate(
        scan_id=scan_id,
        profile=ScanProfile.STANDARD_ACTIVE,
        findings=enriched,
        scan_plan=plan,
        passive_executed=True,
        active_analyzers_executed=list(active_ids),
        urls_crawled=1,
    )
    a01 = next(e for e in cov.owasp_categories if e.owasp_id == "A01:2021")
    assert "ACT-TRAVERSAL-ANALYZER" in a01.checks_executed
    assert "ACT-API-SEC-ANALYZER" in a01.checks_executed
