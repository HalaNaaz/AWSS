import pytest
from backend.app.core.exceptions import ScopeViolationError, SSRFValidationError
from backend.app.scanner.scope.scope_gate import ScopeGate
from shared.schemas.common import ScopeRuleType


def test_scope_gate_url_in_scope():
    gate = ScopeGate(
        target_base_url="https://app.example.com",
        scope_rules=[
            (ScopeRuleType.INCLUDE, r"^https?://app\.example\.com/.*$"),
            (ScopeRuleType.EXCLUDE, r"^https?://app\.example\.com/logout.*$")
        ]
    )

    # In scope
    assert gate.validate_url_in_scope("https://app.example.com/dashboard") is True
    assert gate.validate_url_in_scope("https://app.example.com/api/users") is True

    # Excluded explicitly
    assert gate.validate_url_in_scope("https://app.example.com/logout") is False
    assert gate.validate_url_in_scope("https://app.example.com/logout?confirm=true") is False

    # Out of scope domain
    assert gate.validate_url_in_scope("https://evil.com/payload") is False
    assert gate.validate_url_in_scope("https://sub.example.com/test") is False


def test_scope_gate_prohibited_ips():
    gate = ScopeGate(target_base_url="https://example.com")

    # RFC 1918 Private
    assert gate.is_ip_prohibited("10.0.0.1") is True
    assert gate.is_ip_prohibited("172.16.50.4") is True
    assert gate.is_ip_prohibited("192.168.1.1") is True

    # Loopback
    assert gate.is_ip_prohibited("127.0.0.1") is True
    assert gate.is_ip_prohibited("127.0.0.53") is True

    # Cloud Metadata (RFC 3927)
    assert gate.is_ip_prohibited("169.254.169.254") is True

    # Public IP (Safe to scan if authorized)
    assert gate.is_ip_prohibited("93.184.216.34") is False


def test_scope_gate_pre_flight_scope_violation():
    gate = ScopeGate(target_base_url="https://app.example.com")
    with pytest.raises(ScopeViolationError):
        gate.pre_flight_check("https://unauthorized-domain.com/login")
