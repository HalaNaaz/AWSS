import time
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from backend.app.scanner.active.models import ActiveFinding
from backend.app.scanner.intelligence.confidence import ConfidenceEngine
from backend.app.scanner.intelligence.correlator import CorrelationEngine
from backend.app.scanner.intelligence.engine import VulnerabilityIntelligenceEngine
from backend.app.scanner.intelligence.normalizer import FindingNormalizer
from backend.app.scanner.intelligence.remediation import RemediationIntelligenceEngine
from backend.app.scanner.intelligence.risk_engine import ContextualRiskEngine
from backend.app.scanner.intelligence.validation import SafeValidationWorkflow
from backend.app.scanner.passive.models import PassiveFinding
from shared.schemas.common import FindingStatus, Severity
from shared.schemas.discovery import (
    APIEndpointSchema,
    APIType,
    ParameterCategory,
    ParameterIntelligenceSchema,
    ParameterLocation,
    TechnologyObservationSchema,
)
from shared.schemas.intelligence import (
    ConfidenceLevel,
    ContextualPriority,
    CorrelationRelationship,
    ValidationState,
)


def test_normalization_across_passive_active_and_malformed_dicts():
    scan_id = uuid4()
    target_id = uuid4()
    techs = [
        TechnologyObservationSchema(
            scan_id=scan_id,
            technology_name="FastAPI",
            category="backend-framework",
            confidence=0.95,
            detection_source="HTTP Headers",
        )
    ]

    passive = PassiveFinding(
        rule_id="PASSIVE-HDR-CSP-MISSING",
        title="Missing Content-Security-Policy Header",
        description="CSP missing",
        cwe_id="CWE-693",
        owasp_category="A05:2021 - Security Misconfiguration",
        severity=Severity.MEDIUM,
        cvss_score=5.0,
        url="https://app.example.com/login/",
        evidence_request="GET /login HTTP/1.1\r\nAuthorization: Bearer super_secret_jwt_123",
        evidence_response="HTTP/1.1 200 OK\r\nSet-Cookie: session=abc_secret_cookie; Path=/",
        remediation="Set CSP.",
    )
    passive.seal_evidence()

    active = ActiveFinding(
        rule_id="ACT-XSS-REFLECTED-HTML",
        title="Reflected Cross-Site Scripting (HTML Context)",
        description="Unescaped canary",
        cwe_id="CWE-79",
        owasp_category="A03:2021 - Injection",
        severity=Severity.HIGH,
        cvss_score=7.5,
        status=FindingStatus.VERIFIED,
        confidence=0.95,
        url="https://app.example.com/search?b=2&a=1",
        parameter="q",
        http_method="GET",
        evidence_request="GET /search?q=ashlynx123 HTTP/1.1",
        evidence_response="HTTP/1.1 200 OK\n<html>ashlynx123</html>",
        remediation="Encode output.",
        detection_module="xss_analyzer",
    )

    malformed = {
        "title": "  ",
        "cwe_id": "89",
        "severity": "INVALID_SEV",
        "cvss_score": 99.0,  # out of bounds -> clamped
        "confidence": "not-a-float",
        "url": "app.example.com/api/items",
        "parameter": " id ",
        "evidence": {
            "request": "Authorization: Bearer leak_token_999",
            "response": '{"password": "plaintext_password_123"}',
        },
    }

    normalized = FindingNormalizer.normalize_batch(
        [passive, active, malformed, "not-even-a-finding"],
        scan_id=scan_id,
        target_id=target_id,
        technologies=techs,
    )

    assert len(normalized) == 3

    nf_passive, nf_active, nf_malformed = normalized
    assert nf_passive.vulnerability_category == "SECURITY_HEADERS"
    assert nf_passive.endpoint_path == "/login"
    assert "app.example.com" in nf_passive.asset_relationships
    assert "FastAPI" in nf_passive.technology_relationships
    assert "super_secret_jwt_123" not in nf_passive.evidence.request
    assert "[REDACTED]" in nf_passive.evidence.request
    assert "abc_secret_cookie" not in nf_passive.evidence.response

    assert nf_active.vulnerability_category == "XSS"
    assert nf_active.normalized_endpoint == "https://app.example.com/search?a=1&b=2"
    assert nf_active.detection_method == "active_two_phase"

    assert nf_malformed.cwe_id == "CWE-89"
    assert nf_malformed.cvss_score == 10.0
    assert nf_malformed.severity == Severity.MEDIUM
    assert nf_malformed.affected_parameter == "id"
    assert "leak_token_999" not in nf_malformed.evidence.request
    assert "plaintext_password_123" not in nf_malformed.evidence.response


def test_fingerprint_determinism_across_url_variants():
    n1 = FindingNormalizer.normalize({
        "title": "SQL Injection",
        "cwe_id": "CWE-89",
        "url": "https://SHOP.Example.com/items/?page=2&sort=asc",
        "parameter": "id",
        "method": "get",
        "rule_id": "ACT-SQLI-BOOL",
    })
    n2 = FindingNormalizer.normalize({
        "title": "SQL Injection",
        "cwe_id": "89",
        "url": "https://shop.example.com/items",
        "parameter": "ID",
        "method": "GET",
        "rule_id": "act-sqli-bool",
    })
    assert n1.fingerprint == n2.fingerprint


def test_correlation_distinguishes_duplicates_related_systemic_and_independent():
    scan_id = uuid4()

    # Exact duplicate pair (active verified vs suspected/passive same vector)
    f_dup_verified = FindingNormalizer.normalize(ActiveFinding(
        rule_id="ACT-XSS-HTML",
        title="Reflected XSS",
        description="Verified canary",
        cwe_id="CWE-79",
        owasp_category="A03:2021 - Injection",
        severity=Severity.HIGH,
        cvss_score=7.5,
        status=FindingStatus.VERIFIED,
        confidence=0.95,
        url="https://app.local/search?q=test",
        parameter="q",
        evidence_request="GET /search?q=canary HTTP/1.1",
        evidence_response="<html>canary</html>",
        remediation="Escape HTML",
        detection_module="xss_analyzer",
    ), scan_id=scan_id)

    f_dup_secondary = FindingNormalizer.normalize(ActiveFinding(
        rule_id="ACT-XSS-HTML",
        title="Reflected XSS",
        description="Secondary anomaly",
        cwe_id="CWE-79",
        owasp_category="A03:2021 - Injection",
        severity=Severity.HIGH,
        cvss_score=7.5,
        status=FindingStatus.SUSPECTED,
        confidence=0.65,
        url="https://app.local/search?q=other",
        parameter="q",
        evidence_request="GET /search?q=canary HTTP/1.1",
        evidence_response="<html>canary</html>",
        remediation="Escape HTML",
        detection_module="xss_analyzer",
    ), scan_id=scan_id)

    # Related security header on same /search endpoint (XSS <-> SECURITY_HEADERS)
    f_related_csp = FindingNormalizer.normalize({
        "id": str(uuid4()),
        "title": "Missing CSP Header",
        "cwe_id": "CWE-693",
        "severity": "MEDIUM",
        "cvss_score": 5.0,
        "url": "https://app.local/search",
        "rule_id": "PASSIVE-HDR-CSP",
    }, scan_id=scan_id)

    # Systemic pattern across two distinct endpoints on same asset
    f_sys_1 = FindingNormalizer.normalize({
        "id": str(uuid4()),
        "title": "Server Banner Disclosure",
        "cwe_id": "CWE-200",
        "severity": "LOW",
        "cvss_score": 3.1,
        "url": "https://app.local/about",
        "rule_id": "PASSIVE-INFO-SERVER",
    }, scan_id=scan_id)
    f_sys_2 = FindingNormalizer.normalize({
        "id": str(uuid4()),
        "title": "Server Banner Disclosure",
        "cwe_id": "CWE-200",
        "severity": "LOW",
        "cvss_score": 3.1,
        "url": "https://app.local/contact",
        "rule_id": "PASSIVE-INFO-SERVER",
    }, scan_id=scan_id)

    # Independent finding on different path & unrelated CWE
    f_indep = FindingNormalizer.normalize({
        "id": str(uuid4()),
        "title": "Missing Anti-CSRF Token",
        "cwe_id": "CWE-352",
        "severity": "MEDIUM",
        "cvss_score": 5.5,
        "url": "https://app.local/profile/update",
        "method": "POST",
        "rule_id": "PASSIVE-HTML-CSRF",
    }, scan_id=scan_id)

    corr = CorrelationEngine.correlate([
        f_dup_secondary,
        f_dup_verified,
        f_related_csp,
        f_sys_1,
        f_sys_2,
        f_indep,
    ])

    # Primary verified selected over suspected duplicate
    assert corr.finding_map[f_dup_verified.id]["correlation_relationship"] == CorrelationRelationship.DUPLICATE
    assert corr.finding_map[f_dup_verified.id]["is_primary"] is True
    assert corr.finding_map[f_dup_verified.id]["is_duplicate"] is False

    assert corr.finding_map[f_dup_secondary.id]["is_duplicate"] is True
    assert corr.finding_map[f_dup_secondary.id]["duplicate_of"] == f_dup_verified.id

    # Related linked cleanly
    assert corr.finding_map[f_related_csp.id]["correlation_relationship"] == CorrelationRelationship.RELATED
    assert f_dup_verified.id in corr.finding_map[f_related_csp.id]["related_finding_ids"]

    # Systemic pattern grouped as POTENTIALLY_CORRELATED and NOT marked duplicate
    assert corr.finding_map[f_sys_1.id]["correlation_relationship"] == CorrelationRelationship.POTENTIALLY_CORRELATED
    assert corr.finding_map[f_sys_1.id]["is_duplicate"] is False
    assert corr.finding_map[f_sys_2.id]["is_duplicate"] is False

    # Independent stays INDEPENDENT
    assert corr.finding_map[f_indep.id]["correlation_relationship"] == CorrelationRelationship.INDEPENDENT


def test_confidence_assessment_separates_high_severity_from_low_confidence():
    # High severity SQLi alert WITH WAF 403 contradiction and missing secondary confirmation
    waf_blocked = FindingNormalizer.normalize({
        "title": "Possible SQL Injection",
        "cwe_id": "CWE-89",
        "severity": "HIGH",
        "cvss_score": 8.2,
        "status": "SUSPECTED",
        "confidence": 0.45,
        "url": "https://app.local/items?id=1",
        "parameter": "id",
        "detection_method": "active_probe",
        "evidence": {
            "request": "GET /items?id=1' HTTP/1.1",
            "response": "HTTP/1.1 403 Forbidden\nCloudflare WAF Block - Access Denied",
        },
    })

    assess = ConfidenceEngine.assess(waf_blocked)
    assert assess.level == ConfidenceLevel.LOW
    assert assess.needs_manual_review is True
    assert len(assess.contradictory_signals) > 0
    assert "LOW confidence" in assess.explanation

    # High-confidence verified finding
    verified_sqli = FindingNormalizer.normalize(ActiveFinding(
        rule_id="ACT-SQLI-BOOL",
        title="Boolean-Based SQL Injection",
        description="Deterministic invariant verified",
        cwe_id="CWE-89",
        owasp_category="A03:2021 - Injection",
        severity=Severity.CRITICAL,
        cvss_score=9.4,
        status=FindingStatus.VERIFIED,
        confidence=0.95,
        url="https://app.local/items?id=1",
        parameter="id",
        evidence_request="GET /items?id=1%20AND%208943%3D8943 HTTP/1.1",
        evidence_response="HTTP/1.1 200 OK\nItem Record Found",
        remediation="Use parameterized queries.",
        detection_module="sqli_analyzer",
    ))

    high_assess = ConfidenceEngine.assess(verified_sqli, has_parameter_intel=True)
    assert high_assess.level == ConfidenceLevel.HIGH
    assert high_assess.needs_manual_review is False
    assert high_assess.corroborated is True


def test_validation_lifecycle_controls_and_risk_separation():
    scan_id = uuid4()
    raw_low_conf_high_sev = {
        "id": str(uuid4()),
        "title": "Unconfirmed SSRF Probe",
        "cwe_id": "CWE-918",
        "severity": "HIGH",
        "cvss_score": 8.0,
        "status": "SUSPECTED",
        "confidence": 0.4,
        "url": "https://app.local/fetch?target=http://example.com",
        "parameter": "target",
        "detection_method": "active_probe",
    }

    enriched, summary = VulnerabilityIntelligenceEngine.process_findings(
        [raw_low_conf_high_sev],
        scan_id=scan_id,
        asset_criticality=None,  # Explicitly unconfigured
    )
    assert len(enriched) == 1
    finding = enriched[0]
    intel = finding.intelligence
    assert intel is not None

    # Guard downgraded initial state to NEEDS_REVIEW instead of VALIDATED
    assert intel.confidence_assessment.level in (ConfidenceLevel.LOW, ConfidenceLevel.MEDIUM)
    assert intel.validation_state == ValidationState.NEEDS_REVIEW
    # CVSS untouched, Contextual Priority capped & data limitations reported
    assert finding.cvss_score == 8.0
    assert intel.contextual_risk.cvss_baseline == 8.0
    assert intel.contextual_risk.asset_criticality_used is None
    assert any("Asset criticality not configured" in d for d in intel.contextual_risk.data_limitations)

    # Illegal auto-promote blocked when confidence is LOW
    intel.confidence_assessment.level = ConfidenceLevel.LOW
    with pytest.raises(ValueError):
        SafeValidationWorkflow.transition(
            finding,
            ValidationState.VALIDATED,
            validation_method="automated_auto_promote",
        )

    # Valid analyst review transition
    updated = SafeValidationWorkflow.transition(
        finding,
        ValidationState.FALSE_POSITIVE,
        actor="qa_engineer",
        notes="Verified benign redirect behavior",
        supporting_evidence="Authorization: Bearer secret_evidence_token",
    )
    assert updated.intelligence.validation_state == ValidationState.FALSE_POSITIVE
    assert updated.status == FindingStatus.FALSE_POSITIVE
    assert len(updated.intelligence.validation_history) == 2
    assert "secret_evidence_token" not in updated.intelligence.validation_history[-1].supporting_evidence

    # Illegal jump from FALSE_POSITIVE -> VALIDATED without passing NEEDS_REVIEW
    with pytest.raises(ValueError):
        SafeValidationWorkflow.transition(updated, ValidationState.VALIDATED)


def test_contextual_risk_reflects_analyst_criticality_without_altering_cvss():
    nf = FindingNormalizer.normalize(ActiveFinding(
        rule_id="ACT-XSS-HTML",
        title="Reflected XSS",
        description="Verified",
        cwe_id="CWE-79",
        owasp_category="A03:2021 - Injection",
        severity=Severity.HIGH,
        cvss_score=7.5,
        status=FindingStatus.VERIFIED,
        confidence=0.95,
        url="https://app.local/api/v1/search?q=test",
        parameter="q",
        evidence_request="GET /api/v1/search?q=x HTTP/1.1",
        evidence_response="HTTP/1.1 200 OK\n<html>x</html>",
        remediation="Escape.",
        detection_module="xss_analyzer",
    ))
    conf = ConfidenceEngine.assess(nf)
    apis = [
        APIEndpointSchema(
            url="https://app.local/api/v1/search?q=test",
            method="GET",
            api_type=APIType.REST,
            auth_required=False,
            parameters=["q"],
            discovery_source="CRAWLER",
            confidence=0.9,
        )
    ]
    params = [
        ParameterIntelligenceSchema(
            name="q",
            location=ParameterLocation.QUERY,
            category=ParameterCategory.SEARCH,
            confidence=0.9,
            endpoints_found=[nf.normalized_endpoint],
        )
    ]

    risk_low_crit = ContextualRiskEngine.assess(nf, conf, asset_criticality=0.5, endpoint_apis=apis, endpoint_parameters=params)
    risk_high_crit = ContextualRiskEngine.assess(nf, conf, asset_criticality=5.0, endpoint_apis=apis, endpoint_parameters=params)

    assert risk_high_crit.contextual_score > risk_low_crit.contextual_score
    assert risk_high_crit.cvss_baseline == 7.5
    assert risk_low_crit.cvss_baseline == 7.5
    assert risk_high_crit.asset_criticality_used == 5.0


def test_remediation_intelligence_cwe_specificity():
    nf_sqli = FindingNormalizer.normalize({
        "title": "SQL Injection",
        "cwe_id": "CWE-89",
        "severity": "HIGH",
        "cvss_score": 8.5,
        "url": "https://app.local/users",
        "parameter": "id",
    })
    conf = ConfidenceEngine.assess(nf_sqli)
    risk = ContextualRiskEngine.assess(nf_sqli, conf)
    rem = RemediationIntelligenceEngine.generate(nf_sqli, risk)

    assert "parameterized" in rem.recommended_remediation.lower()
    assert "CWE-89" in rem.cwe_references
    assert any("A03:2021" in o for o in rem.owasp_references)
    assert "id" in rem.affected_component


def test_correlation_performance_on_large_dataset():
    scan_id = uuid4()
    raw_batch = [
        {
            "id": str(uuid4()),
            "title": f"Missing Header {i % 5}",
            "cwe_id": f"CWE-{693 if i % 2 == 0 else 200}",
            "severity": "LOW",
            "cvss_score": 3.1,
            "url": f"https://app.local/page/{i % 50}",
            "rule_id": f"PASSIVE-RULE-{i % 5}",
            "evidence": {"request": "GET /", "response": "HTTP/1.1 200 OK"},
        }
        for i in range(500)
    ]
    start = time.perf_counter()
    enriched, summary = VulnerabilityIntelligenceEngine.process_findings(raw_batch, scan_id=scan_id)
    elapsed = time.perf_counter() - start

    assert len(enriched) == 500
    assert summary.duplicate_findings_count > 0
    assert elapsed < 2.0  # Safeguard: 500 findings correlated well within 2s


@pytest.mark.asyncio
async def test_safe_revalidation_workflow_header_confirm_and_resolved():
    from unittest.mock import AsyncMock, MagicMock, patch
    scan_id = uuid4()
    raw = {
        "id": str(uuid4()),
        "title": "Missing Content-Security-Policy Header",
        "cwe_id": "CWE-693",
        "severity": "MEDIUM",
        "cvss_score": 5.0,
        "url": "https://app.example.com/about",
        "rule_id": "PASSIVE-HDR-CSP-MISSING",
    }
    enriched, _ = VulnerabilityIntelligenceEngine.process_findings([raw], scan_id=scan_id)
    finding = enriched[0]

    # Case 1: Header still missing -> VALIDATED
    mock_resp_missing = MagicMock(status_code=200, headers={"Content-Type": "text/html"}, text="<html></html>")
    mock_client_1 = MagicMock()
    mock_client_1.__aenter__ = AsyncMock(return_value=mock_client_1)
    mock_client_1.__aexit__ = AsyncMock(return_value=False)
    mock_client_1.get = AsyncMock(return_value=(mock_resp_missing, None))

    with patch("backend.app.scanner.intelligence.validation.AsyncHTTPClient", return_value=mock_client_1):
        updated, passed, _ = await SafeValidationWorkflow.run_safe_revalidation(
            finding=finding,
            target_base_url="https://app.example.com",
            authorized=True,
        )
        assert passed is True
        assert updated.intelligence.validation_state == ValidationState.VALIDATED

    # Case 2: Header added -> RESOLVED
    mock_resp_fixed = MagicMock(
        status_code=200,
        headers={"Content-Type": "text/html", "Content-Security-Policy": "default-src 'self'"},
        text="<html></html>",
    )
    mock_client_2 = MagicMock()
    mock_client_2.__aenter__ = AsyncMock(return_value=mock_client_2)
    mock_client_2.__aexit__ = AsyncMock(return_value=False)
    mock_client_2.get = AsyncMock(return_value=(mock_resp_fixed, None))

    # Transition to NEEDS_REVIEW first to verify re-check moves it to RESOLVED
    SafeValidationWorkflow.transition(finding, ValidationState.NEEDS_REVIEW, actor="qa")
    with patch("backend.app.scanner.intelligence.validation.AsyncHTTPClient", return_value=mock_client_2):
        updated2, passed2, _ = await SafeValidationWorkflow.run_safe_revalidation(
            finding=finding,
            target_base_url="https://app.example.com",
            authorized=True,
        )
        assert passed2 is False
        assert updated2.intelligence.validation_state == ValidationState.RESOLVED

