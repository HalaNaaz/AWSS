from collections import Counter
from typing import List
from uuid import UUID

from backend.app.scanner.evidence.redactor import EvidenceRedactor
from shared.schemas.common import FindingStatus
from shared.schemas.finding import FindingResponse
from shared.schemas.phase6 import EvidenceIntelligenceSummarySchema


class EvidenceIntelligenceEngine:
    """Phase 6F: Scan-Level Assessment Evidence Intelligence & Integrity Aggregator.

    Evaluates evidence completeness, SHA-256 chain-of-custody seals, redaction
    compliance, source provenance, reproducibility tiers, and contradictory evidence.
    """

    @classmethod
    def summarize(cls, scan_id: UUID, findings: List[FindingResponse]) -> EvidenceIntelligenceSummarySchema:
        if not findings:
            return EvidenceIntelligenceSummarySchema(scan_id=scan_id)

        total_ev = 0
        sealed = 0
        unsealed = 0
        missing = 0
        contradictions = 0
        redaction_clean = True
        provenance_counter: Counter = Counter()
        repro_counter: Counter = Counter()
        conf_scores: List[float] = []

        for f in findings:
            conf_scores.append(f.confidence)
            if f.evidence:
                total_ev += 1
                if len(f.evidence.sha256_hash or "") == 64:
                    sealed += 1
                else:
                    unsealed += 1

                # Verify redaction safety (ensure raw Bearer/Basic credentials never leaked)
                if f.evidence.request != EvidenceRedactor.redact(f.evidence.request) or f.evidence.response != EvidenceRedactor.redact(f.evidence.response):
                    redaction_clean = False

                provenance_counter[f.evidence.probe_type or "primary"] += 1
            else:
                missing += 1
                provenance_counter["missing_evidence"] += 1

            if f.intelligence:
                if f.intelligence.confidence_assessment.contradictory_signals:
                    contradictions += 1

                if f.status == FindingStatus.VERIFIED:
                    repro_counter["DETERMINISTIC_VERIFIED"] += 1
                elif f.curl_reproduction or (f.evidence and f.evidence.request and f.evidence.response):
                    repro_counter["PINNED_REPRODUCIBLE"] += 1
                elif f.evidence:
                    repro_counter["PARTIAL"] += 1
                else:
                    repro_counter["UNREPRODUCIBLE"] += 1
            else:
                repro_counter["PINNED_REPRODUCIBLE" if f.evidence else "UNREPRODUCIBLE"] += 1

        avg_conf = round(sum(conf_scores) / len(conf_scores), 3) if conf_scores else 0.0

        return EvidenceIntelligenceSummarySchema(
            scan_id=scan_id,
            total_evidence_records=total_ev,
            sealed_sha256_count=sealed,
            unsealed_count=unsealed,
            redacted_secrets_confirmed=redaction_clean,
            source_provenance_breakdown=dict(provenance_counter),
            reproducibility_breakdown=dict(repro_counter),
            contradictory_evidence_count=contradictions,
            missing_evidence_count=missing,
            average_confidence_score=avg_conf,
        )
