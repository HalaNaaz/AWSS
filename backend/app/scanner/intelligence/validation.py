from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

from backend.app.core.config import settings
from backend.app.scanner.crawler.client import AsyncHTTPClient
from backend.app.scanner.evidence.redactor import EvidenceRedactor
from backend.app.scanner.scope.scope_gate import ScopeGate
from shared.schemas.common import FindingStatus, Severity
from shared.schemas.finding import FindingResponse
from shared.schemas.intelligence import (
    ConfidenceLevel,
    ValidationHistoryEntrySchema,
    ValidationState,
)


class SafeValidationWorkflow:
    """Phase 5E: Controlled & Traceable Safe Vulnerability Validation Lifecycle.

    Manages controlled transitions across validation states, enforces safety
    invariants (e.g., preventing unverified HIGH-severity/LOW-confidence auto-confirmation),
    records immutable audit history, and supports bounded ScopeGate-enforced
    non-destructive re-validation checks.
    """

    ALLOWED_TRANSITIONS: Dict[ValidationState, Set[ValidationState]] = {
        ValidationState.DETECTED: {
            ValidationState.NEEDS_REVIEW,
            ValidationState.VALIDATION_PENDING,
            ValidationState.VALIDATED,
            ValidationState.INCONCLUSIVE,
            ValidationState.FALSE_POSITIVE,
            ValidationState.ACCEPTED_RISK,
            ValidationState.RESOLVED,
        },
        ValidationState.NEEDS_REVIEW: {
            ValidationState.VALIDATION_PENDING,
            ValidationState.VALIDATED,
            ValidationState.INCONCLUSIVE,
            ValidationState.FALSE_POSITIVE,
            ValidationState.ACCEPTED_RISK,
            ValidationState.RESOLVED,
        },
        ValidationState.VALIDATION_PENDING: {
            ValidationState.VALIDATED,
            ValidationState.INCONCLUSIVE,
            ValidationState.NEEDS_REVIEW,
            ValidationState.FALSE_POSITIVE,
            ValidationState.RESOLVED,
        },
        ValidationState.VALIDATED: {
            ValidationState.ACCEPTED_RISK,
            ValidationState.RESOLVED,
            ValidationState.FALSE_POSITIVE,
            ValidationState.NEEDS_REVIEW,
        },
        ValidationState.INCONCLUSIVE: {
            ValidationState.NEEDS_REVIEW,
            ValidationState.VALIDATION_PENDING,
            ValidationState.VALIDATED,
            ValidationState.FALSE_POSITIVE,
            ValidationState.ACCEPTED_RISK,
            ValidationState.RESOLVED,
        },
        ValidationState.FALSE_POSITIVE: {
            ValidationState.NEEDS_REVIEW,
            ValidationState.VALIDATION_PENDING,
        },
        ValidationState.ACCEPTED_RISK: {
            ValidationState.NEEDS_REVIEW,
            ValidationState.RESOLVED,
        },
        ValidationState.RESOLVED: {
            ValidationState.NEEDS_REVIEW,
            ValidationState.VALIDATION_PENDING,
        },
    }

    VALIDATION_TO_FINDING_STATUS: Dict[ValidationState, FindingStatus] = {
        ValidationState.DETECTED: FindingStatus.DETECTED,
        ValidationState.NEEDS_REVIEW: FindingStatus.SUSPECTED,
        ValidationState.VALIDATION_PENDING: FindingStatus.VERIFICATION_PENDING,
        ValidationState.VALIDATED: FindingStatus.VERIFIED,
        ValidationState.INCONCLUSIVE: FindingStatus.INCONCLUSIVE,
        ValidationState.FALSE_POSITIVE: FindingStatus.FALSE_POSITIVE,
        ValidationState.ACCEPTED_RISK: FindingStatus.ACCEPTED_RISK,
        ValidationState.RESOLVED: FindingStatus.RESOLVED,
    }

    @classmethod
    def determine_initial_state(
        cls,
        original_status: FindingStatus,
        severity: Severity,
        confidence_level: ConfidenceLevel,
        needs_manual_review: bool,
    ) -> Tuple[ValidationState, ValidationHistoryEntrySchema]:
        """Determines safe initial validation state and creates opening audit record."""
        # Guard: Never auto-validate HIGH/CRITICAL findings with LOW confidence
        if severity in (Severity.CRITICAL, Severity.HIGH) and confidence_level == ConfidenceLevel.LOW:
            state = ValidationState.NEEDS_REVIEW
            method = "confidence_guard_triage"
            notes = "High/Critical severity finding downgraded to NEEDS_REVIEW due to LOW evidence confidence."
        elif original_status == FindingStatus.VERIFIED and confidence_level == ConfidenceLevel.HIGH:
            state = ValidationState.VALIDATED
            method = "automated_two_phase_verification"
            notes = "Validated during active Phase 2 deterministic verification."
        elif original_status in (FindingStatus.SUSPECTED, FindingStatus.VERIFICATION_PENDING):
            state = ValidationState.NEEDS_REVIEW if needs_manual_review else ValidationState.VALIDATION_PENDING
            method = "initial_detection_triage"
            notes = "Anomaly detected; pending deterministic validation or analyst review."
        elif needs_manual_review or confidence_level == ConfidenceLevel.LOW:
            state = ValidationState.NEEDS_REVIEW
            method = "initial_confidence_triage"
            notes = "Flagged for manual review based on evidence quality assessment."
        else:
            state = ValidationState.DETECTED
            method = "passive_or_deterministic_detection"
            notes = "Initial state assigned upon normalized ingestion."

        entry = ValidationHistoryEntrySchema(
            from_state=None,
            to_state=state,
            timestamp=datetime.now(timezone.utc),
            actor="avive_engine",
            validation_method=method,
            notes=notes,
        )
        return (state, entry)

    @classmethod
    def transition(
        cls,
        finding: FindingResponse,
        target_state: ValidationState,
        actor: str = "analyst",
        validation_method: str = "manual_review",
        supporting_evidence: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> FindingResponse:
        """Executes a controlled validation state transition and appends immutable audit log."""
        if not finding.intelligence:
            raise ValueError("Finding has not been enriched with AVIVE intelligence metadata.")

        current_state = finding.intelligence.validation_state
        if current_state == target_state:
            return finding

        allowed = cls.ALLOWED_TRANSITIONS.get(current_state, set())
        if target_state not in allowed:
            raise ValueError(
                f"Illegal validation transition from '{current_state.value}' to '{target_state.value}'. "
                f"Allowed targets: {[s.value for s in sorted(allowed, key=lambda x: x.value)]}"
            )

        # Prevent automated promotion of LOW-confidence findings to VALIDATED without evidence
        if (
            target_state == ValidationState.VALIDATED
            and finding.intelligence.confidence_assessment.level == ConfidenceLevel.LOW
            and validation_method == "automated_auto_promote"
        ):
            raise ValueError(
                "Policy violation: Cannot auto-promote a LOW confidence finding to VALIDATED without verification evidence."
            )

        redacted_support: Optional[str] = None
        support_hash: Optional[str] = None
        if supporting_evidence:
            redacted_support = EvidenceRedactor.redact(supporting_evidence)
            support_hash = EvidenceRedactor.generate_sha256_seal("VALIDATION_SUPPORT", redacted_support)

        history_entry = ValidationHistoryEntrySchema(
            from_state=current_state,
            to_state=target_state,
            timestamp=datetime.now(timezone.utc),
            actor=actor.strip() or "analyst",
            validation_method=validation_method.strip() or "manual_review",
            supporting_evidence=redacted_support,
            evidence_sha256=support_hash,
            notes=notes,
        )

        finding.intelligence.validation_state = target_state
        finding.intelligence.validation_history.append(history_entry)
        if target_state == ValidationState.VALIDATED:
            finding.intelligence.confidence_assessment.needs_manual_review = False

        # Synchronize backward-compatible top-level FindingStatus
        finding.status = cls.VALIDATION_TO_FINDING_STATUS.get(target_state, finding.status)
        finding.updated_at = datetime.now(timezone.utc)
        return finding

    @classmethod
    async def run_safe_revalidation(
        cls,
        finding: FindingResponse,
        target_base_url: str,
        authorized: bool = False,
        actor: str = "analyst",
        allow_private_ips: Optional[bool] = None,
    ) -> Tuple[FindingResponse, bool, str]:
        """Executes a bounded, non-destructive safe re-verification probe strictly through ScopeGate.

        Returns (updated_finding, validation_passed, message).
        """
        if not authorized:
            raise PermissionError(
                "Unauthorized validation action blocked: explicit target authorization confirmation is required."
            )
        if not finding.intelligence:
            raise ValueError("Finding missing AVIVE intelligence context.")

        use_private = settings.ALLOW_PRIVATE_IPS if allow_private_ips is None else allow_private_ips
        scope_gate = ScopeGate(target_base_url=target_base_url, allow_private_ips=use_private)

        url = finding.endpoint.url
        # Strict ScopeGate pre-flight check before opening any network client
        if not scope_gate.validate_url_in_scope(url):
            raise PermissionError(f"ScopeGate blocked validation probe: '{url}' is out of scope or SSRF-prohibited.")

        # Perform non-destructive read-only GET check to verify reachability & passive/header status
        async with AsyncHTTPClient(scope_gate=scope_gate, rate_limit_rps=5.0, max_retries=1) as client:
            resp, req_err = await client.get(url)

        if resp is None:
            updated = cls.transition(
                finding=finding,
                target_state=ValidationState.INCONCLUSIVE,
                actor=actor,
                validation_method="safe_scopegate_reprobe",
                notes=f"Re-validation request failed or blocked by ScopeGate: {req_err or 'no response'}",
            )
            return (updated, False, f"Re-validation inconclusive: {req_err or 'target unreachable'}")

        redacted_resp = EvidenceRedactor.redact(
            f"HTTP {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items()) + f"\n\n{(resp.text or '')[:400]}"
        )
        cat = finding.intelligence.vulnerability_category

        # Evaluate safe non-destructive checks by category
        if cat == "SECURITY_HEADERS":
            header_names = {k.lower() for k in resp.headers.keys()}
            title_lower = finding.title.lower()
            still_missing = (
                ("content-security-policy" in title_lower and "content-security-policy" not in header_names)
                or ("strict-transport-security" in title_lower and "strict-transport-security" not in header_names)
                or ("x-content-type-options" in title_lower and "x-content-type-options" not in header_names)
                or ("x-frame-options" in title_lower and "x-frame-options" not in header_names)
                or ("referrer-policy" in title_lower and "referrer-policy" not in header_names)
                or ("permissions-policy" in title_lower and "permissions-policy" not in header_names)
            )
            if still_missing:
                updated = cls.transition(
                    finding=finding,
                    target_state=ValidationState.VALIDATED,
                    actor=actor,
                    validation_method="safe_passive_header_recheck",
                    supporting_evidence=redacted_resp,
                    notes="Confirmed security header deficiency persists via safe ScopeGate GET check.",
                )
                return (updated, True, "Security header omission confirmed.")
            else:
                updated = cls.transition(
                    finding=finding,
                    target_state=ValidationState.RESOLVED,
                    actor=actor,
                    validation_method="safe_passive_header_recheck",
                    supporting_evidence=redacted_resp,
                    notes="Security header is now present in HTTP response.",
                )
                return (updated, False, "Security header appears remediated (RESOLVED).")

        # For other findings, record safe reachability & mark NEEDS_REVIEW or VALIDATED if already proven
        if resp.status_code < 400 and finding.status == FindingStatus.VERIFIED:
            updated = cls.transition(
                finding=finding,
                target_state=ValidationState.VALIDATED,
                actor=actor,
                validation_method="safe_endpoint_recheck",
                supporting_evidence=redacted_resp,
                notes=f"Target endpoint remains active (HTTP {resp.status_code}); prior deterministic proof stands.",
            )
            return (updated, True, "Endpoint active and finding verified.")

        updated = cls.transition(
            finding=finding,
            target_state=ValidationState.INCONCLUSIVE,
            actor=actor,
            validation_method="safe_endpoint_recheck",
            supporting_evidence=redacted_resp,
            notes=f"Safe non-destructive GET returned HTTP {resp.status_code}; manual analyst verification advised.",
        )
        return (updated, False, "Safe re-check completed; manual verification recommended.")
