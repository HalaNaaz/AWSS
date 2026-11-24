from typing import Optional, Dict, Any


class AshlynxException(Exception):
    """Base exception class for Ashlynx WebSec Scanner."""

    def __init__(self, message: str, code: str = "INTERNAL_ERROR", details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.details = details or {}


class ScopeViolationError(AshlynxException):
    """Raised when an outbound request attempts to access an out-of-scope target."""

    def __init__(self, target_url: str, rule: Optional[str] = None):
        super().__init__(
            message=f"Target URL '{target_url}' violates active scope boundary rules.",
            code="SCOPE_VIOLATION",
            details={"target_url": target_url, "rule": rule}
        )


class SSRFValidationError(AshlynxException):
    """Raised when an outbound connection attempts to resolve or connect to restricted IP space."""

    def __init__(self, hostname: str, resolved_ip: str, reason: str = "Restricted IP address"):
        super().__init__(
            message=f"Anti-SSRF Gate blocked connection to '{hostname}' (resolved: {resolved_ip}): {reason}",
            code="SSRF_PROHIBITED",
            details={"hostname": hostname, "resolved_ip": resolved_ip, "reason": reason}
        )


class TargetVerificationError(AshlynxException):
    """Raised when target ownership verification challenge fails."""

    def __init__(self, target_url: str, reason: str):
        super().__init__(
            message=f"Target ownership verification failed for '{target_url}': {reason}",
            code="TARGET_VERIFICATION_FAILED",
            details={"target_url": target_url, "reason": reason}
        )


class ResourceNotFoundError(AshlynxException):
    """Raised when a requested resource does not exist or is inaccessible in tenant scope."""

    def __init__(self, resource_type: str, identifier: str):
        super().__init__(
            message=f"{resource_type} '{identifier}' not found.",
            code="RESOURCE_NOT_FOUND",
            details={"resource_type": resource_type, "identifier": identifier}
        )


class ScanConfigurationError(AshlynxException):
    """Raised when scan profile, report parameters, or paths are invalid."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            code="SCAN_CONFIG_ERROR",
            details=details or {}
        )
