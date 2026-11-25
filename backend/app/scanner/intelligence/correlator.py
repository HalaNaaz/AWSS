import hashlib
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from uuid import UUID

from backend.app.scanner.intelligence.normalizer import NormalizedFinding
from shared.schemas.common import FindingStatus, Severity
from shared.schemas.intelligence import (
    CorrelationGroupSchema,
    CorrelationRelationship,
)


@dataclass
class CorrelationResult:
    """Output of the cross-module correlation and deduplication pass."""

    finding_map: Dict[UUID, Dict] = field(default_factory=dict)
    groups: List[CorrelationGroupSchema] = field(default_factory=list)


class CorrelationEngine:
    """Phase 5C: Finding Correlation & Deduplication Engine.

    Groups normalized findings across passive and active modules without silently
    discarding evidence. Explicitly classifies pairs/groups as:
    - DUPLICATE: Same weakness, endpoint path, method, parameter, and/or matching fingerprint.
    - RELATED: Different weaknesses sharing the same endpoint/parameter or complementary risk chain
      (e.g. Cookie Secure flag + Cleartext HTTP, or XSS + Missing CSP).
    - POTENTIALLY_CORRELATED: Same CWE/category observed across multiple endpoints of the same asset
      (e.g. site-wide missing security header or systemic config flaw).
    - INDEPENDENT: No meaningful correlation.
    """

    SEVERITY_WEIGHT: Dict[Severity, int] = {
        Severity.CRITICAL: 5,
        Severity.HIGH: 4,
        Severity.MEDIUM: 3,
        Severity.LOW: 2,
        Severity.INFORMATIONAL: 1,
    }

    STATUS_WEIGHT: Dict[FindingStatus, int] = {
        FindingStatus.VERIFIED: 5,
        FindingStatus.SUSPECTED: 3,
        FindingStatus.VERIFICATION_PENDING: 3,
        FindingStatus.DETECTED: 2,
        FindingStatus.UNVERIFIED: 1,
    }

    RELATED_CATEGORY_PAIRS: Set[Tuple[str, str]] = {
        ("XSS", "SECURITY_HEADERS"),
        ("SECURITY_HEADERS", "XSS"),
        ("COOKIE_SECURITY", "TRANSPORT_SECURITY"),
        ("TRANSPORT_SECURITY", "COOKIE_SECURITY"),
        ("AUTHENTICATION_SESSION", "COOKIE_SECURITY"),
        ("COOKIE_SECURITY", "AUTHENTICATION_SESSION"),
        ("AUTHENTICATION_SESSION", "CSRF"),
        ("CSRF", "AUTHENTICATION_SESSION"),
        ("CORS_MISCONFIGURATION", "INFORMATION_DISCLOSURE"),
        ("INFORMATION_DISCLOSURE", "CORS_MISCONFIGURATION"),
        ("SQL_INJECTION", "INFORMATION_DISCLOSURE"),
        ("INFORMATION_DISCLOSURE", "SQL_INJECTION"),
    }

    TOKEN_RE = re.compile(r"[a-z0-9_]{3,}", re.IGNORECASE)

    @classmethod
    def _evidence_tokens(cls, finding: NormalizedFinding) -> Set[str]:
        if not finding.evidence:
            return set()
        text = f"{finding.evidence.request} {finding.evidence.response[:600]}"
        return set(cls.TOKEN_RE.findall(text.lower()))

    @classmethod
    def _evidence_similarity(cls, f1: NormalizedFinding, f2: NormalizedFinding) -> float:
        if f1.evidence and f2.evidence and f1.evidence.sha256_hash == f2.evidence.sha256_hash:
            return 1.0
        t1 = cls._evidence_tokens(f1)
        t2 = cls._evidence_tokens(f2)
        if not t1 or not t2:
            return 0.0
        intersection = len(t1 & t2)
        union = len(t1 | t2)
        return round(intersection / union, 3) if union > 0 else 0.0

    @classmethod
    def _select_primary(cls, members: List[NormalizedFinding]) -> NormalizedFinding:
        """Deterministically selects the highest-quality primary finding in a group."""
        def score_key(f: NormalizedFinding) -> Tuple[int, int, int, int, float, str]:
            is_verified = cls.STATUS_WEIGHT.get(f.original_status, 1)
            is_active = 1 if "active" in f.detection_source.lower() or "active" in f.detection_method.lower() else 0
            has_evidence = 1 if (f.evidence and f.evidence.response) else 0
            sev = cls.SEVERITY_WEIGHT.get(f.severity, 1)
            return (is_verified, is_active, has_evidence, sev, f.original_confidence, str(f.id))

        return max(members, key=score_key)

    @classmethod
    def _group_id(cls, relationship: CorrelationRelationship, key_seed: str) -> str:
        digest = hashlib.sha256(f"{relationship.value}:{key_seed}".encode("utf-8")).hexdigest()[:12]
        return f"corr-{relationship.value.lower()[:4]}-{digest}"

    @classmethod
    def correlate(cls, findings: List[NormalizedFinding]) -> CorrelationResult:
        """Correlates and deduplicates normalized findings safely without discarding originals."""
        result = CorrelationResult()
        if not findings:
            return result

        # Initialize independent defaults
        for f in findings:
            result.finding_map[f.id] = {
                "correlation_group_id": None,
                "correlation_relationship": CorrelationRelationship.INDEPENDENT,
                "correlation_confidence": 0.0,
                "correlation_explanation": "No duplicate or correlated findings detected.",
                "is_primary": True,
                "is_duplicate": False,
                "duplicate_of": None,
                "related_finding_ids": [],
            }

        assigned_duplicate_ids: Set[UUID] = set()
        groups: List[CorrelationGroupSchema] = []

        # 1. Exact & Near-Exact Duplicate Clustering
        # Bucket A: identical fingerprint (CWE + category + path + method + param + rule_id)
        fp_buckets: Dict[str, List[NormalizedFinding]] = defaultdict(list)
        for f in findings:
            fp_buckets[f.fingerprint].append(f)

        # Bucket B: cross-rule / cross-module identical vector (CWE + path + method + param)
        vector_buckets: Dict[Tuple[str, str, str, Optional[str]], List[NormalizedFinding]] = defaultdict(list)
        for f in findings:
            vkey = (
                f.cwe_id,
                f.endpoint_path.lower(),
                f.http_method.upper(),
                (f.affected_parameter or "").lower() or None,
            )
            vector_buckets[vkey].append(f)

        # First cluster strict fingerprint matches
        for fp, bucket in fp_buckets.items():
            if len(bucket) > 1:
                primary = cls._select_primary(bucket)
                gid = cls._group_id(CorrelationRelationship.DUPLICATE, fp)
                member_ids = [m.id for m in bucket]
                shared = [f"fingerprint:{fp}", f"cwe:{primary.cwe_id}", f"path:{primary.endpoint_path}"]
                if primary.affected_parameter:
                    shared.append(f"parameter:{primary.affected_parameter}")
                explanation = (
                    f"Exact duplicate across {len(bucket)} detections sharing fingerprint "
                    f"({primary.cwe_id} on {primary.http_method} {primary.endpoint_path}"
                    + (f", param '{primary.affected_parameter}'" if primary.affected_parameter else "")
                    + ")."
                )
                groups.append(
                    CorrelationGroupSchema(
                        group_id=gid,
                        relationship_type=CorrelationRelationship.DUPLICATE,
                        primary_finding_id=primary.id,
                        member_finding_ids=member_ids,
                        correlation_confidence=0.98,
                        explanation=explanation,
                        cwe_id=primary.cwe_id,
                        shared_attributes=shared,
                    )
                )
                for m in bucket:
                    is_prim = m.id == primary.id
                    result.finding_map[m.id].update({
                        "correlation_group_id": gid,
                        "correlation_relationship": CorrelationRelationship.DUPLICATE,
                        "correlation_confidence": 0.98,
                        "correlation_explanation": explanation,
                        "is_primary": is_prim,
                        "is_duplicate": not is_prim,
                        "duplicate_of": None if is_prim else primary.id,
                        "related_finding_ids": [mid for mid in member_ids if mid != m.id],
                    })
                    if not is_prim:
                        assigned_duplicate_ids.add(m.id)

        # Next check cross-module vector buckets where rules differ but CWE + endpoint + method + param match
        for vkey, bucket in vector_buckets.items():
            # Only consider unassigned findings or expand existing group
            unassigned = [f for f in bucket if f.id not in assigned_duplicate_ids and result.finding_map[f.id]["correlation_group_id"] is None]
            if len(unassigned) > 1:
                # Verify semantic or evidence match before marking duplicate (don't merge blindly!)
                primary = cls._select_primary(unassigned)
                dup_members = [primary]
                for cand in unassigned:
                    if cand.id == primary.id:
                        continue
                    sim = cls._evidence_similarity(primary, cand)
                    same_category = primary.vulnerability_category == cand.vulnerability_category
                    if same_category and (sim >= 0.35 or (primary.affected_parameter and primary.affected_parameter == cand.affected_parameter)):
                        dup_members.append(cand)

                if len(dup_members) > 1:
                    gid = cls._group_id(CorrelationRelationship.DUPLICATE, "|".join(str(x) for x in vkey))
                    member_ids = [m.id for m in dup_members]
                    conf = 0.90
                    explanation = (
                        f"Cross-module duplicate cluster ({len(dup_members)} findings) for {primary.cwe_id} "
                        f"affecting {primary.http_method} {primary.endpoint_path}"
                        + (f" parameter '{primary.affected_parameter}'" if primary.affected_parameter else "")
                        + "."
                    )
                    groups.append(
                        CorrelationGroupSchema(
                            group_id=gid,
                            relationship_type=CorrelationRelationship.DUPLICATE,
                            primary_finding_id=primary.id,
                            member_finding_ids=member_ids,
                            correlation_confidence=conf,
                            explanation=explanation,
                            cwe_id=primary.cwe_id,
                            shared_attributes=[f"cwe:{primary.cwe_id}", f"path:{primary.endpoint_path}", f"method:{primary.http_method}"],
                        )
                    )
                    for m in dup_members:
                        is_prim = m.id == primary.id
                        result.finding_map[m.id].update({
                            "correlation_group_id": gid,
                            "correlation_relationship": CorrelationRelationship.DUPLICATE,
                            "correlation_confidence": conf,
                            "correlation_explanation": explanation,
                            "is_primary": is_prim,
                            "is_duplicate": not is_prim,
                            "duplicate_of": None if is_prim else primary.id,
                            "related_finding_ids": [mid for mid in member_ids if mid != m.id],
                        })
                        if not is_prim:
                            assigned_duplicate_ids.add(m.id)

        # 2. Related Findings (distinct weaknesses on the same endpoint path or related security chains)
        primary_findings = [f for f in findings if f.id not in assigned_duplicate_ids]
        by_endpoint: Dict[str, List[NormalizedFinding]] = defaultdict(list)
        for f in primary_findings:
            by_endpoint[f.endpoint_path.lower()].append(f)

        for ep_path, ep_list in by_endpoint.items():
            if len(ep_list) < 2:
                continue
            for i in range(len(ep_list)):
                for j in range(i + 1, len(ep_list)):
                    f1, f2 = ep_list[i], ep_list[j]
                    pair_cats = (f1.vulnerability_category, f2.vulnerability_category)
                    same_param = bool(f1.affected_parameter and f2.affected_parameter and f1.affected_parameter == f2.affected_parameter)
                    if pair_cats in cls.RELATED_CATEGORY_PAIRS or same_param:
                        # Link related IDs bidirectionally
                        if f2.id not in result.finding_map[f1.id]["related_finding_ids"]:
                            result.finding_map[f1.id]["related_finding_ids"].append(f2.id)
                        if f1.id not in result.finding_map[f2.id]["related_finding_ids"]:
                            result.finding_map[f2.id]["related_finding_ids"].append(f1.id)

                        # Upgrade INDEPENDENT to RELATED if not already part of a duplicate group
                        for fx in (f1, f2):
                            if result.finding_map[fx.id]["correlation_relationship"] == CorrelationRelationship.INDEPENDENT:
                                reason = (
                                    f"Shares parameter '{f1.affected_parameter}' on {ep_path}"
                                    if same_param
                                    else f"Complementary risk relationship ({f1.vulnerability_category} <-> {f2.vulnerability_category}) on {ep_path}"
                                )
                                result.finding_map[fx.id]["correlation_relationship"] = CorrelationRelationship.RELATED
                                result.finding_map[fx.id]["correlation_confidence"] = 0.80 if same_param else 0.72
                                result.finding_map[fx.id]["correlation_explanation"] = reason

        # Record RELATED groups for endpoints with related primary clusters
        for ep_path, ep_list in by_endpoint.items():
            related_members = [
                f for f in ep_list
                if result.finding_map[f.id]["correlation_relationship"] == CorrelationRelationship.RELATED
                and result.finding_map[f.id]["correlation_group_id"] is None
            ]
            if len(related_members) >= 2:
                primary = cls._select_primary(related_members)
                gid = cls._group_id(CorrelationRelationship.RELATED, ep_path)
                member_ids = [m.id for m in related_members]
                explanation = (
                    f"{len(related_members)} distinct but security-related findings co-located on endpoint '{ep_path}'."
                )
                groups.append(
                    CorrelationGroupSchema(
                        group_id=gid,
                        relationship_type=CorrelationRelationship.RELATED,
                        primary_finding_id=primary.id,
                        member_finding_ids=member_ids,
                        correlation_confidence=0.75,
                        explanation=explanation,
                        cwe_id=None,
                        shared_attributes=[f"path:{ep_path}"],
                    )
                )
                for m in related_members:
                    result.finding_map[m.id]["correlation_group_id"] = gid

        # 3. Potentially Correlated (Site-wide / Systemic same CWE+rule across multiple endpoints on same asset)
        by_asset_rule: Dict[Tuple[str, str, Optional[str]], List[NormalizedFinding]] = defaultdict(list)
        for f in primary_findings:
            if result.finding_map[f.id]["correlation_group_id"] is not None:
                continue
            asset = f.asset_relationships[0] if f.asset_relationships else "default"
            by_asset_rule[(asset, f.cwe_id, f.rule_id or f.title.lower())].append(f)

        for (asset, cwe_id, rule_key), cluster in by_asset_rule.items():
            if len(cluster) >= 2:
                primary = cls._select_primary(cluster)
                gid = cls._group_id(CorrelationRelationship.POTENTIALLY_CORRELATED, f"{asset}:{cwe_id}:{rule_key}")
                member_ids = [m.id for m in cluster]
                explanation = (
                    f"Systemic pattern: {len(cluster)} independent occurrences of {cwe_id} ({primary.title}) "
                    f"observed across multiple endpoints on asset '{asset}'."
                )
                groups.append(
                    CorrelationGroupSchema(
                        group_id=gid,
                        relationship_type=CorrelationRelationship.POTENTIALLY_CORRELATED,
                        primary_finding_id=primary.id,
                        member_finding_ids=member_ids,
                        correlation_confidence=0.68,
                        explanation=explanation,
                        cwe_id=cwe_id,
                        shared_attributes=[f"asset:{asset}", f"cwe:{cwe_id}"],
                    )
                )
                for m in cluster:
                    result.finding_map[m.id].update({
                        "correlation_group_id": gid,
                        "correlation_relationship": CorrelationRelationship.POTENTIALLY_CORRELATED,
                        "correlation_confidence": 0.68,
                        "correlation_explanation": explanation,
                        # Systemic observations across different URLs are NOT duplicates; all remain primary
                        "is_primary": True,
                        "is_duplicate": False,
                        "related_finding_ids": list(set(result.finding_map[m.id]["related_finding_ids"]) | {mid for mid in member_ids if mid != m.id}),
                    })

        result.groups = groups
        return result
