from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import httpx
import pytest

from backend.app.scanner.crawler.client import AsyncHTTPClient
from backend.app.scanner.discovery.engine import AttackSurfaceIntelligenceEngine
from backend.app.scanner.intelligence.analytics import SecurityAnalyticsEngine
from backend.app.scanner.intelligence.context_assessor import ContextAwareAssessor
from backend.app.scanner.intelligence.coverage import SecurityCoverageEngine
from backend.app.scanner.intelligence.engine import VulnerabilityIntelligenceEngine
from backend.app.scanner.intelligence.evidence_intel import EvidenceIntelligenceEngine
from backend.app.scanner.intelligence.planner import IntelligentScanPlanner
from backend.app.scanner.scope.scope_gate import ScopeGate
from shared.schemas.common import FindingStatus, ScanProfile, ScanStatus, Severity
from shared.schemas.phase6 import CoverageStatus
from shared.schemas.report import SeveritySummarySchema, UnifiedScanReport


def test_intelligent_scan_planner_prunes_static_and_enforces_scope():
    scan_id = uuid4()
    gate = ScopeGate(target_base_url="https://app.example.com", allow_private_ips=False)
    disc = AttackSurfaceIntelligenceEngine(
        target_base_url="https://app.example.com",
        scope_gate=gate,
        scan_id=scan_id,
    )

    disc.ingest_crawled_page("https://app.example.com/search?q=test", status_code=200, content_type="text/html")
    disc.ingest_crawled_page("https://app.example.com/redirect?dest=/home", status_code=302, content_type="text/html")
    disc.ingest_crawled_page("https://app.example.com/login", status_code=200, content_type="text/html")
    disc.ingest_crawled_page("https://app.example.com/static/style.css", status_code=200, content_type="text/css")
    disc.ingest_crawled_page("https://app.example.com/static/logo.png", status_code=200, content_type="image/png")

    plan = IntelligentScanPlanner.build_plan(
        scan_id=scan_id,
        target_url="https://app.example.com",
        profile=ScanProfile.SAFE_ACTIVE,
        scope_gate=gate,
        discovery_engine=disc,
        request_budget=60,
    )

    assert plan.scope_enforced is True
    assert plan.allocated_probe_budget == 60
    assert plan.estimated_total_probes <= 60
    assert plan.planned_targets_count >= 3
    assert plan.skipped_targets_count >= 2

    planned_urls = {p.url for p in plan.planned_checks}
    assert "https://app.example.com/static/style.css" not in planned_urls
    assert "https://app.example.com/static/logo.png" not in planned_urls

    search_plan = next(p for p in plan.planned_checks if "/search" in p.url)
    assert "ACT-SQLI-ANALYZER" in search_plan.selected_analyzers
    assert "ACT-XSS-ANALYZER" in search_plan.selected_analyzers

    redirect_plan = next(p for p in plan.planned_checks if "/redirect" in p.url)
    assert "ACT-SSRF-ANALYZER" in redirect_plan.selected_analyzers

    # Passive profile produces 0 active probes
    passive_plan = IntelligentScanPlanner.build_plan(
        scan_id=scan_id,
        target_url="https://app.example.com",
        profile=ScanProfile.PASSIVE_ONLY,
        scope_gate=gate,
        discovery_engine=disc,
    )
    assert passive_plan.planned_targets_count == 0
    assert passive_plan.estimated_total_probes == 0


def test_context_aware_assessor_and_coverage_intelligence():
    scan_id = uuid4()
    gate = ScopeGate(target_base_url="https://app.example.com", allow_private_ips=False)
    disc = AttackSurfaceIntelligenceEngine("https://app.example.com", gate, scan_id)
    disc.ingest_crawled_page("https://app.example.com/redirect?dest=/home", status_code=200)
    disc.ingest_crawled_page("https://app.example.com/login", status_code=200)
    disc.ingest_crawled_page("https://app.example.com/api/v1/items", status_code=200, content_type="application/json")

    raw_findings = [
        {
            "id": str(uuid4()),
            "title": "Missing CSP",
            "cwe_id": "CWE-693",
            "severity": "MEDIUM",
            "cvss_score": 5.0,
            "url": "https://app.example.com/login",
            "evidence": {"request": "GET /login", "response": "HTTP/1.1 200 OK"},
        }
    ]
    enriched, _ = VulnerabilityIntelligenceEngine.process_findings(raw_findings, scan_id=scan_id, discovery_engine=disc)

    ctx_report = ContextAwareAssessor.evaluate(scan_id, disc, enriched)
    assert ctx_report.evaluated_endpoints == 3
    cats = {s.category for s in ctx_report.suggestions}
    assert "OPEN_REDIRECT_SSRF_BOUNDARY" in cats
    assert "AUTH_SESSION_HARDENING" in cats
    assert "PUBLIC_API_ACCESS_CONTROL" in cats

    # Honest coverage: PASSIVE_ONLY skips A03 Injection & A10 SSRF, leaves A09 UNTESTED
    cov_passive = SecurityCoverageEngine.evaluate(
        scan_id=scan_id,
        profile=ScanProfile.PASSIVE_ONLY,
        findings=enriched,
        passive_executed=True,
        active_analyzers_executed=[],
        urls_crawled=3,
    )
    assert cov_passive.overall_dast_coverage_percent < 100.0
    by_id = {c.owasp_id: c for c in cov_passive.owasp_categories}
    assert by_id["A03:2021"].status == CoverageStatus.SKIPPED
    assert by_id["A09:2021"].status == CoverageStatus.UNTESTED
    assert by_id["A06:2021"].status == CoverageStatus.PARTIAL

    # SAFE_ACTIVE marks A03 & A10 TESTED when analyzers ran
    cov_active = SecurityCoverageEngine.evaluate(
        scan_id=scan_id,
        profile=ScanProfile.SAFE_ACTIVE,
        findings=enriched,
        passive_executed=True,
        active_analyzers_executed=["ACT-SQLI-ANALYZER", "ACT-XSS-ANALYZER", "ACT-MISCONFIG-ANALYZER", "ACT-SSRF-ANALYZER"],
        urls_crawled=3,
    )
    by_id_act = {c.owasp_id: c for c in cov_active.owasp_categories}
    assert by_id_act["A03:2021"].status == CoverageStatus.TESTED
    assert by_id_act["A10:2021"].status == CoverageStatus.TESTED
    assert cov_active.overall_dast_coverage_percent > cov_passive.overall_dast_coverage_percent


@pytest.mark.asyncio
async def test_http_client_bounded_retry_and_metrics():
    gate = ScopeGate(target_base_url="https://app.example.com", allow_private_ips=False)
    async with AsyncHTTPClient(scope_gate=gate, rate_limit_rps=10.0, max_retries=1) as client:
        resp_429 = MagicMock(status_code=429, headers={})
        resp_200 = MagicMock(status_code=200, headers={"content-length": "12"}, text="OK")
        with patch.object(gate, "pre_flight_check", return_value="93.184.216.34"):
            with patch.object(client._client, "request", new=AsyncMock(side_effect=[resp_429, resp_200])):
                with patch("asyncio.sleep", new=AsyncMock()):
                    resp, err = await client.get("https://app.example.com/")
                    assert err is None
                    assert resp.status_code == 200
                    assert client.metrics["rate_limited_429"] == 1
                    assert client.metrics["retried"] == 1
                    assert client.metrics["succeeded"] == 1


def test_evidence_intelligence_and_real_analytics_comparison():
    scan_a = uuid4()
    scan_b = uuid4()
    f_a1, _ = VulnerabilityIntelligenceEngine.process_findings([
        {
            "id": str(uuid4()),
            "title": "Missing CSP",
            "cwe_id": "CWE-693",
            "severity": "MEDIUM",
            "cvss_score": 5.0,
            "url": "https://app.example.com/",
            "evidence": {"request": "GET /", "response": "HTTP/1.1 200 OK"},
        },
        {
            "id": str(uuid4()),
            "title": "Reflected XSS",
            "cwe_id": "CWE-79",
            "severity": "HIGH",
            "cvss_score": 7.5,
            "status": "VERIFIED",
            "url": "https://app.example.com/search?q=x",
            "parameter": "q",
            "evidence": {"request": "GET /search?q=x", "response": "<html>x</html>"},
        },
    ], scan_id=scan_a)

    # Scan B fixed XSS, kept CSP, introduced HSTS gap
    f_b1, _ = VulnerabilityIntelligenceEngine.process_findings([
        {
            "id": str(uuid4()),
            "title": "Missing CSP",
            "cwe_id": "CWE-693",
            "severity": "MEDIUM",
            "cvss_score": 5.0,
            "url": "https://app.example.com/",
            "evidence": {"request": "GET /", "response": "HTTP/1.1 200 OK"},
        },
        {
            "id": str(uuid4()),
            "title": "Missing HSTS",
            "cwe_id": "CWE-319",
            "severity": "LOW",
            "cvss_score": 3.1,
            "url": "https://app.example.com/",
            "evidence": {"request": "GET /", "response": "HTTP/1.1 200 OK"},
        },
    ], scan_id=scan_b)

    ev_sum = EvidenceIntelligenceEngine.summarize(scan_a, f_a1)
    assert ev_sum.total_evidence_records == 2
    assert ev_sum.sealed_sha256_count == 2
    assert ev_sum.redacted_secrets_confirmed is True

    # Empty analytics returns zero-state (no synthetic data)
    empty_analytics = SecurityAnalyticsEngine.compute_analytics([])
    assert empty_analytics.total_scans_analyzed == 0
    assert empty_analytics.total_findings_across_scans == 0

    rep_a = UnifiedScanReport(
        scan_id=scan_a,
        target_url="https://app.example.com",
        profile=ScanProfile.SAFE_ACTIVE,
        status=ScanStatus.COMPLETED,
        severity_summary=SeveritySummarySchema.from_findings(f_a1),
        findings=f_a1,
    )
    rep_b = UnifiedScanReport(
        scan_id=scan_b,
        target_url="https://app.example.com",
        profile=ScanProfile.SAFE_ACTIVE,
        status=ScanStatus.COMPLETED,
        severity_summary=SeveritySummarySchema.from_findings(f_b1),
        findings=f_b1,
    )

    analytics = SecurityAnalyticsEngine.compute_analytics([rep_a, rep_b])
    assert analytics.total_scans_analyzed == 2
    assert analytics.total_findings_across_scans == 4

    diff = SecurityAnalyticsEngine.compare_scans(rep_a, rep_b)
    assert diff.new_findings_count == 1
    assert diff.resolved_findings_count == 1
    assert diff.persisting_findings_count == 1
