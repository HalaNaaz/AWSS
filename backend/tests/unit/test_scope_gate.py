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


def test_scope_gate_prohibited_ipv4_and_metadata():
    gate = ScopeGate(target_base_url="https://example.com")

    # RFC 1918 Private Ranges
    assert gate.is_ip_prohibited("10.0.0.1") is True
    assert gate.is_ip_prohibited("10.255.255.255") is True
    assert gate.is_ip_prohibited("172.16.50.4") is True
    assert gate.is_ip_prohibited("172.31.255.255") is True
    assert gate.is_ip_prohibited("192.168.1.1") is True
    assert gate.is_ip_prohibited("192.168.254.254") is True

    # Loopback
    assert gate.is_ip_prohibited("127.0.0.1") is True
    assert gate.is_ip_prohibited("127.0.0.53") is True

    # Cloud Metadata (RFC 3927)
    assert gate.is_ip_prohibited("169.254.169.254") is True
    assert gate.is_ip_prohibited("169.254.0.1") is True

    # Multicast & Reserved
    assert gate.is_ip_prohibited("224.0.0.1") is True
    assert gate.is_ip_prohibited("240.0.0.1") is True
    assert gate.is_ip_prohibited("0.0.0.0") is True

    # Valid Public IP (Allowed)
    assert gate.is_ip_prohibited("93.184.216.34") is False
    assert gate.is_ip_prohibited("8.8.8.8") is False


def test_scope_gate_prohibited_ipv6_and_mapped():
    gate = ScopeGate(target_base_url="https://example.com")

    # IPv6 Loopback
    assert gate.is_ip_prohibited("::1") is True

    # IPv6 Link-Local
    assert gate.is_ip_prohibited("fe80::1") is True

    # IPv6 Unique Local Address (ULA)
    assert gate.is_ip_prohibited("fc00::1") is True
    assert gate.is_ip_prohibited("fd12:3456:789a:1::1") is True

    # IPv4-Mapped IPv6 addressing (Evasion technique)
    assert gate.is_ip_prohibited("::ffff:127.0.0.1") is True
    assert gate.is_ip_prohibited("::ffff:169.254.169.254") is True
    assert gate.is_ip_prohibited("::ffff:10.0.0.1") is True
    assert gate.is_ip_prohibited("::ffff:192.168.1.1") is True

    # Unspecified address
    assert gate.is_ip_prohibited("::") is True

    # Carrier-Grade NAT (RFC 6598), Benchmarking (RFC 2544), IANA protocol, and IPv6 documentation ranges
    assert gate.is_ip_prohibited("100.64.0.1") is True
    assert gate.is_ip_prohibited("100.127.255.254") is True
    assert gate.is_ip_prohibited("192.0.0.8") is True
    assert gate.is_ip_prohibited("198.18.0.1") is True
    assert gate.is_ip_prohibited("198.19.255.254") is True
    assert gate.is_ip_prohibited("2001:db8::1") is True
    assert gate.is_ip_prohibited("::ffff:100.64.0.1") is True


def test_scope_gate_redirect_validation():
    gate = ScopeGate(target_base_url="https://app.example.com")

    # Out-of-scope redirect destination raises ScopeViolationError
    with pytest.raises(ScopeViolationError):
        gate.validate_redirect("https://evil.com/attacker")

    # Out-of-scope internal IP URL raises ScopeViolationError first
    with pytest.raises(ScopeViolationError):
        gate.validate_redirect("http://169.254.169.254/latest/meta-data/")


def test_scope_gate_dns_rebinding_resistance():
    """Validates that ScopeGate resolves DNS and returns a pinned IP to prevent TOCTOU rebinding."""
    gate = ScopeGate(target_base_url="https://localhost")
    # Attempting to resolve localhost or private host triggers SSRFValidationError
    with pytest.raises(SSRFValidationError) as exc_info:
        gate.resolve_and_pin("localhost")
    assert "127.0.0.1" in exc_info.value.message or "::1" in exc_info.value.message or "Restricted" in exc_info.value.message
