from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID

from backend.app.scanner.discovery.engine import AttackSurfaceIntelligenceEngine
from backend.app.scanner.intelligence.confidence import ConfidenceEngine
from backend.app.scanner.intelligence.correlator import CorrelationEngine
from backend.app.scanner.intelligence.normalizer import FindingNormalizer, NormalizedFinding
from backend.app.scanner.intelligence.remediation import RemediationIntelligenceEngine
from backend.app.scanner.intelligence.risk_engine import ContextualRiskEngine
from backend.app.scanner.intelligence.validation import SafeValidationWorkflow
from shared.schemas.discovery import (
    APIEndpointSchema,
    ParameterIntelligenceSchema,
    TechnologyObservationSchema,
)
from shared.schemas.finding import EndpointSchema, FindingResponse
from shared.schemas.intelligence import (
    CorrelationRelationship,
    FindingIntelligenceSchema,
    RemediationStatus,
    ScanIntelligenceSummarySchema,
)


class VulnerabilityIntelligenceEngine:
    """Master Coordinator for Phase 5: Advanced Vulnerability Intelligence & Validation Engine (AVIVE).

    Coordinates:
    - Phase 5B: Unified Finding Normalization
    - Phase 5C: Finding Correlation & Deduplication
    - Phase 5D: Evidence Quality & Explainable Confidence Assessment
    - Phase 5E: Safe Validation Lifecycle Initialization
    - Phase 5F: Contextual Risk Assessment
    - Phase 5G: Evidence-Grounded Remediation Intelligence
    """

    @classmethod
    def process_findings(
        cls,
        raw_findings: List[Any],
        scan_id: UUID,
        target_id: Optional[UUID] = None,
        technologies: Optional[List[TechnologyObservationSchema]] = None,
        discovery_engine: Optional[AttackSurfaceIntelligenceEngine] = None,
        asset_criticality: Optional[float] = None,
    ) -> Tuple[List[FindingResponse], ScanIntelligenceSummarySchema]:
        """Processes raw scan findings through the full AVIVE intelligence pipeline."""
        if not raw_findings:
            return ([], ScanIntelligenceSummarySchema(scan_id=scan_id))

        # 1. Phase 5B: Normalize all raw records safely
        normalized_list: List[NormalizedFinding] = FindingNormalizer.normalize_batch(
            raw_findings=raw_findings,
            scan_id=scan_id,
            target_id=target_id,
            technologies=technologies,
        )

        if not normalized_list:
            return ([], ScanIntelligenceSummarySchema(scan_id=scan_id))

        # Extract Phase 4 attack surface lookups if available
        apis_list: List[APIEndpointSchema] = []
        params_by_url: Dict[str, List[ParameterIntelligenceSchema]] = defaultdict(list)
        if discovery_engine:
            try:
                apis_list = discovery_engine.api_engine.get_apis()
                for param in discovery_engine.parameter_engine.get_all_parameters():
                    for ep_url in param.endpoints_found:
                        params_by_url[ep_url.lower()].append(param)
            except Exception:
                pass

        # 2. Phase 5C: Correlate & deduplicate without discarding originals
        corr_result = CorrelationEngine.correlate(normalized_list)

        enriched_responses: List[FindingResponse] = []
        conf_counter: Counter = Counter()
        val_counter: Counter = Counter()
        risk_counter: Counter = Counter()
        manual_review_count = 0
        dup_count = 0
        primary_count = 0

        for nf in normalized_list:
            corr_info = corr_result.finding_map.get(nf.id, {})
            ep_params = params_by_url.get(nf.normalized_endpoint.lower(), [])
            has_param_intel = bool(ep_params)

            # 3. Phase 5D: Confidence Assessment
            confidence_assess = ConfidenceEngine.assess(
                finding=nf,
                correlation_info=corr_info,
                has_parameter_intel=has_param_intel,
            )

            # 4. Phase 5E: Safe Validation Initial State & Audit Trail
            val_state, init_history = SafeValidationWorkflow.determine_initial_state(
                original_status=nf.original_status,
                severity=nf.severity,
                confidence_level=confidence_assess.level,
                needs_manual_review=confidence_assess.needs_manual_review,
            )

            # 5. Phase 5F: Contextual Risk Assessment
            risk_assess = ContextualRiskEngine.assess(
                finding=nf,
                confidence_assessment=confidence_assess,
                correlation_info=corr_info,
                asset_criticality=asset_criticality,
                endpoint_apis=apis_list,
                endpoint_parameters=ep_params,
            )

            # 6. Phase 5G: Remediation Intelligence
            rem_intel = RemediationIntelligenceEngine.generate(
                finding=nf,
                contextual_risk=risk_assess,
                existing_status=RemediationStatus.OPEN,
            )

            is_primary = bool(corr_info.get("is_primary", True))
            is_dup = bool(corr_info.get("is_duplicate", False))
            if is_dup:
                dup_count += 1
            if is_primary:
                primary_count += 1
            if confidence_assess.needs_manual_review:
                manual_review_count += 1

            conf_counter[confidence_assess.level.value] += 1
            val_counter[val_state.value] += 1
            risk_counter[risk_assess.contextual_priority.value] += 1

            intel_schema = FindingIntelligenceSchema(
                fingerprint=nf.fingerprint,
                vulnerability_category=nf.vulnerability_category,
                target_id=nf.target_id,
                normalized_endpoint=nf.normalized_endpoint,
                http_method=nf.http_method,
                parameter=nf.affected_parameter,
                asset_relationships=nf.asset_relationships,
                technology_relationships=nf.technology_relationships,
                detection_source=nf.detection_source,
                detection_method=nf.detection_method,
                evidence_references=nf.evidence_references,
                correlation_group_id=corr_info.get("correlation_group_id"),
                correlation_relationship=corr_info.get("correlation_relationship", CorrelationRelationship.INDEPENDENT),
                correlation_confidence=float(corr_info.get("correlation_confidence", 0.0)),
                correlation_explanation=corr_info.get("correlation_explanation"),
                is_primary=is_primary,
                is_duplicate=is_dup,
                duplicate_of=corr_info.get("duplicate_of"),
                related_finding_ids=list(corr_info.get("related_finding_ids", [])),
                confidence_assessment=confidence_assess,
                validation_state=val_state,
                validation_history=[init_history],
                contextual_risk=risk_assess,
                remediation_intelligence=rem_intel,
                raw_module_metadata=nf.raw_module_metadata,
            )

            # Synchronize safe status onto FindingResponse without losing original active verification
            compat_status = SafeValidationWorkflow.VALIDATION_TO_FINDING_STATUS.get(val_state, nf.original_status)

            response_obj = FindingResponse(
                id=nf.id,
                scan_id=nf.scan_id,
                target_id=nf.target_id,
                title=nf.title,
                description=nf.description or None,
                cwe_id=nf.cwe_id,
                owasp_category=nf.owasp_category,
                severity=nf.severity,
                cvss_score=nf.cvss_score,
                cvss_vector=nf.cvss_vector,
                status=compat_status,
                confidence=confidence_assess.score,
                remediation=rem_intel.recommended_remediation,
                curl_reproduction=nf.curl_reproduction,
                endpoint=EndpointSchema(
                    url=nf.affected_endpoint,
                    method=nf.http_method,
                    parameter=nf.affected_parameter,
                    headers=nf.raw_module_metadata.get("endpoint_headers"),
                ),
                evidence=nf.evidence,
                intelligence=intel_schema,
                created_at=nf.detection_timestamp,
                updated_at=nf.detection_timestamp,
            )
            enriched_responses.append(response_obj)

        # Sort findings by contextual risk score descending so primary high-risk items appear first
        enriched_responses.sort(
            key=lambda f: (
                0 if (f.intelligence and f.intelligence.is_primary) else 1,
                -(f.intelligence.contextual_risk.contextual_score if f.intelligence else 0.0),
                -f.cvss_score,
            )
        )

        summary = ScanIntelligenceSummarySchema(
            scan_id=scan_id,
            total_raw_findings=len(enriched_responses),
            unique_primary_findings=primary_count,
            duplicate_findings_count=dup_count,
            correlation_groups_count=len(corr_result.groups),
            confidence_breakdown=dict(conf_counter),
            validation_state_breakdown=dict(val_counter),
            contextual_priority_breakdown=dict(risk_counter),
            manual_review_required_count=manual_review_count,
            correlation_groups=corr_result.groups,
        )

        return (enriched_responses, summary)

    @classmethod
    def recalculate_risk_for_findings(
        cls,
        findings: List[FindingResponse],
        asset_criticality: float,
        discovery_engine: Optional[AttackSurfaceIntelligenceEngine] = None,
    ) -> Tuple[List[FindingResponse], Dict[str, int]]:
        """Recomputes contextual risk scores for existing findings using analyst-supplied asset criticality."""
        apis_list: List[APIEndpointSchema] = []
        params_by_url: Dict[str, List[ParameterIntelligenceSchema]] = defaultdict(list)
        if discovery_engine:
            try:
                apis_list = discovery_engine.api_engine.get_apis()
                for param in discovery_engine.parameter_engine.get_all_parameters():
                    for ep_url in param.endpoints_found:
                        params_by_url[ep_url.lower()].append(param)
            except Exception:
                pass

        risk_counter: Counter = Counter()
        for f in findings:
            if not f.intelligence:
                continue
            nf = FindingNormalizer.normalize(f, scan_id=f.scan_id, target_id=f.target_id)
            corr_info = {
                "correlation_relationship": f.intelligence.correlation_relationship,
                "related_finding_ids": f.intelligence.related_finding_ids,
            }
            ep_params = params_by_url.get(nf.normalized_endpoint.lower(), [])
            new_risk = ContextualRiskEngine.assess(
                finding=nf,
                confidence_assessment=f.intelligence.confidence_assessment,
                correlation_info=corr_info,
                asset_criticality=asset_criticality,
                endpoint_apis=apis_list,
                endpoint_parameters=ep_params,
            )
            f.intelligence.contextual_risk = new_risk
            # Update remediation priority to align with updated contextual priority
            f.intelligence.remediation_intelligence.remediation_priority = RemediationIntelligenceEngine.PRIORITY_MAP.get(
                new_risk.contextual_priority,
                f.intelligence.remediation_intelligence.remediation_priority,
            )
            risk_counter[new_risk.contextual_priority.value] += 1

        return (findings, dict(risk_counter))
