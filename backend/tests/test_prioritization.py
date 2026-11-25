import pytest
from uuid import uuid4
from backend.app.scanner.discovery.prioritizer import DiscoveryPrioritizationEngine
from backend.app.scanner.discovery.parameter_intelligence import ParameterIntelligenceEngine
from shared.schemas.discovery import DiscoveredEndpointCreate, PriorityLevel, ParameterLocation


def test_prioritization_high_score_auth_and_upload():
    scan_id = uuid4()
    endpoint = DiscoveredEndpointCreate(
        scan_id=scan_id,
        url="https://example.com/admin/upload",
        normalized_url="https://example.com/admin/upload",
        method="POST",
        status_code=403
    )

    param_eng = ParameterIntelligenceEngine()
    params = [param_eng.record_parameter("file", ParameterLocation.BODY, endpoint.normalized_url)]

    prioritized = DiscoveryPrioritizationEngine.prioritize_endpoint(
        endpoint=endpoint,
        parameters=params,
        has_form=True,
        findings_count=1
    )

    # Auth route (+25), File handling (+20), Form target (+10), Findings (+10), Status anomaly (+5)
    assert prioritized.priority_score >= 60.0
    assert prioritized.priority_level == PriorityLevel.HIGH
    assert prioritized.auth_required
    assert len(prioritized.risk_signals) >= 3


def test_prioritization_low_score_static_page():
    scan_id = uuid4()
    endpoint = DiscoveredEndpointCreate(
        scan_id=scan_id,
        url="https://example.com/about",
        normalized_url="https://example.com/about",
        method="GET",
        status_code=200
    )

    prioritized = DiscoveryPrioritizationEngine.prioritize_endpoint(
        endpoint=endpoint
    )

    assert prioritized.priority_score < 30.0
    assert prioritized.priority_level == PriorityLevel.LOW
    assert not prioritized.auth_required


def test_prioritize_all_sorting():
    scan_id = uuid4()
    ep_low = DiscoveredEndpointCreate(scan_id=scan_id, url="https://example.com/terms", normalized_url="https://example.com/terms")
    ep_high = DiscoveredEndpointCreate(scan_id=scan_id, url="https://example.com/api/v1/auth", normalized_url="https://example.com/api/v1/auth", status_code=401)

    sorted_eps = DiscoveryPrioritizationEngine.prioritize_all([ep_low, ep_high])
    assert sorted_eps[0].url == ep_high.normalized_url
    assert sorted_eps[0].priority_score > sorted_eps[1].priority_score
