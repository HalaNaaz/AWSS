import ipaddress
import re
import socket
from typing import List, Optional, Tuple, Dict
from urllib.parse import urlparse

from backend.app.core.exceptions import ScopeViolationError, SSRFValidationError
from backend.app.core.logging import logger
from shared.schemas.common import ScopeRuleType


class ScopeGate:
    """Non-bypassable Scope and Anti-SSRF Socket Egress Enforcement Gate.
    
    Protects against:
    - Time-of-Check to Time-of-Use (TOCTOU) DNS rebinding attacks via socket IP pinning.
    - Scanner self-weaponization against internal infrastructure and cloud metadata.
    - Accidental or malicious out-of-scope fuzzing.
    - Open redirect SSRF pivoting.
    - IPv4-mapped IPv6 evasion attacks.
    """

    # Prohibited IP networks (RFC 1918, Loopback, Cloud Metadata, Link-Local, Reserved)
    PROHIBITED_NETWORKS = [
        ipaddress.ip_network("0.0.0.0/8"),
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("169.254.0.0/16"),       # Cloud metadata & APIPA (RFC 3927)
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("224.0.0.0/4"),         # Multicast
        ipaddress.ip_network("240.0.0.0/4"),         # Reserved
        ipaddress.ip_network("::1/128"),             # IPv6 Loopback
        ipaddress.ip_network("fc00::/7"),            # IPv6 Unique Local
        ipaddress.ip_network("fe80::/10"),           # IPv6 Link-Local
    ]

    def __init__(
        self,
        target_base_url: str,
        scope_rules: Optional[List[Tuple[ScopeRuleType, str]]] = None,
        allow_private_ips: bool = False
    ):
        self.target_base_url = target_base_url
        self.parsed_target = urlparse(target_base_url)
        self.scope_rules = list(scope_rules or [])
        self.allow_private_ips = allow_private_ips
        self.pin_map: Dict[str, str] = {}

        # If no explicit include rules, target base domain is the implicit scope root
        if not any(rule[0] == ScopeRuleType.INCLUDE for rule in self.scope_rules):
            base_pattern = re.escape(self.parsed_target.netloc)
            self.scope_rules.append((ScopeRuleType.INCLUDE, f"^https?://{base_pattern}(/.*)?$"))

    def is_ip_prohibited(self, ip_str: str) -> bool:
        """Determines if a given IP address belongs to a prohibited private/metadata range."""
        if self.allow_private_ips:
            return False

        try:
            ip_obj = ipaddress.ip_address(ip_str)

            # Check standard Python ipaddress properties (covers loopback, private, link-local, multicast, reserved)
            if (
                ip_obj.is_loopback
                or ip_obj.is_private
                or ip_obj.is_link_local
                or ip_obj.is_multicast
                or ip_obj.is_reserved
                or ip_obj.is_unspecified
            ):
                return True

            # Check for IPv4-mapped IPv6 address (e.g. ::ffff:127.0.0.1 or ::ffff:169.254.169.254)
            if getattr(ip_obj, "ipv4_mapped", None):
                v4_obj = ip_obj.ipv4_mapped
                if (
                    v4_obj.is_loopback
                    or v4_obj.is_private
                    or v4_obj.is_link_local
                    or v4_obj.is_multicast
                    or v4_obj.is_reserved
                    or v4_obj.is_unspecified
                ):
                    return True

            # Match against explicit prohibited subnets
            for net in self.PROHIBITED_NETWORKS:
                if ip_obj in net:
                    return True

            return False
        except ValueError:
            # Unparseable IP is rejected by default
            return True

    def resolve_and_pin(self, hostname: str) -> str:
        """Resolves hostname to IP and verifies it against prohibited ranges.
        
        Returns the validated, pinned IP string.
        Raises SSRFValidationError if any resolved IP is prohibited.
        """
        try:
            # Resolve DNS
            addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            if not addr_info:
                raise SSRFValidationError(hostname, "unresolved", "DNS resolution returned no records")
            
            # Verify ALL resolved IPs across IPv4 and IPv6 records
            for entry in addr_info:
                ip_cand = entry[4][0]
                if self.is_ip_prohibited(ip_cand):
                    logger.warning(
                        f"[ScopeGate] Blocked SSRF attempt: {hostname} -> {ip_cand} (prohibited IP detected)"
                    )
                    raise SSRFValidationError(
                        hostname=hostname,
                        resolved_ip=ip_cand,
                        reason="IP is within prohibited RFC 1918 / Cloud Metadata CIDR"
                    )

            # Select first validated IP
            resolved_ip = addr_info[0][4][0]
            self.pin_map[hostname] = resolved_ip
        except (socket.gaierror, Exception) as exc:
            if isinstance(exc, SSRFValidationError):
                raise
            raise SSRFValidationError(hostname, "error", f"DNS resolution failed: {str(exc)}")

        return resolved_ip

    def validate_url_in_scope(self, url: str) -> bool:
        """Checks URL against inclusion and exclusion scope rules."""
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return False

        # First, evaluate exclusion rules (exclusions override inclusions)
        for rule_type, pattern in self.scope_rules:
            if rule_type == ScopeRuleType.EXCLUDE:
                if re.search(pattern, url, re.IGNORECASE):
                    return False

        # Next, evaluate inclusion rules
        for rule_type, pattern in self.scope_rules:
            if rule_type == ScopeRuleType.INCLUDE:
                if re.search(pattern, url, re.IGNORECASE):
                    return True

        return False

    def pre_flight_check(self, url: str) -> str:
        """Complete pre-flight security evaluation for an outbound request.
        
        1. Validates URL against scope boundary rules.
        2. Resolves and pins hostname IP against SSRF rules.
        
        Returns pinned IP address.
        """
        if not self.validate_url_in_scope(url):
            raise ScopeViolationError(target_url=url)

        parsed = urlparse(url)
        hostname = parsed.hostname or parsed.netloc.split(":")[0]
        pinned_ip = self.resolve_and_pin(hostname)
        return pinned_ip

    def validate_redirect(self, redirect_url: str) -> str:
        """Validates an HTTP redirect target URL against scope rules and SSRF protections.
        
        Prevents targets from pivoting the scanner to internal services via HTTP 301/302 redirects.
        Returns pinned IP address if valid; raises ScopeViolationError or SSRFValidationError if unsafe.
        """
        return self.pre_flight_check(redirect_url)
