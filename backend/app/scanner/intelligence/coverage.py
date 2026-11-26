from typing import Dict, List, Optional, Set, Tuple
from uuid import UUID

from shared.schemas.common import ScanProfile
from shared.schemas.finding import FindingResponse
from shared.schemas.phase6 import (
    CoverageStatus,
    OWASPCoverageEntrySchema,
    ScanPlanSchema,
    SecurityCoverageReportSchema,
)


class SecurityCoverageEngine:
    """Phase 6D: Honest, Evidence-Backed OWASP Top 10:2021 Coverage Intelligence Engine.

    Maps executed passive and active checks to OWASP categories, explicitly reports
    TESTED, PARTIAL, SKIPPED, UNTESTED, and INCONCLUSIVE states, and explains why
    checks were skipped without ever fabricating complete coverage.
    """

    OWASP_2021_CATALOG: List[Tuple[str, str, Set[str], str]] = [
        ("A01:2021", "Broken Access Control", {"CORS_MISCONFIGURATION", "OPEN_REDIRECT", "CSRF", "PATH_TRAVERSAL", "API_SECURITY"}, "Passive CORS/CSRF/postMessage & active traversal/redirect/API boundary checks"),
        ("A02:2021", "Cryptographic Failures", {"TRANSPORT_SECURITY", "COOKIE_SECURITY", "CLIENT_SIDE_SECURITY"}, "HTTPS transport, HSTS, mixed content, and cookie Secure flag inspection"),
        ("A03:2021", "Injection", {"SQL_INJECTION", "XSS", "SSTI", "CLIENT_SIDE_SECURITY"}, "Bounded non-destructive SQLi boolean differential, XSS canary, DOM sink, and SSTI math probes"),
        ("A04:2021", "Insecure Design", {"SECURITY_HEADERS"}, "Clickjacking framing & security design header inspection (requires design review for full coverage)"),
        ("A05:2021", "Security Misconfiguration", {"SECURITY_HEADERS", "INFORMATION_DISCLOSURE", "MISCONFIGURATION", "XXE", "CACHE_SECURITY", "API_SECURITY"}, "HTTP headers, cache-control, server banners, stack traces, API schema/introspection, and bounded XXE check"),
        ("A06:2021", "Vulnerable and Outdated Components", set(), "Passive technology fingerprinting only; full CVE/SCA inventory requires manifest scanning"),
        ("A07:2021", "Identification and Authentication Failures", {"AUTHENTICATION_SESSION", "COOKIE_SECURITY", "TOKEN_SECURITY"}, "Session cookie flags, JWT hygiene, CSRF login checks, and auth endpoint inspection"),
        ("A08:2021", "Software and Data Integrity Failures", {"HTML_SECURITY"}, "Subresource Integrity (SRI) passive check; CI/CD artifact signing out of DAST scope"),
        ("A09:2021", "Security Logging and Monitoring Failures", set(), "Not observable via external black-box DAST requests"),
        ("A10:2021", "Server-Side Request Forgery (SSRF)", {"SSRF"}, "Bounded safe SSRF candidate & redirect/URL parameter checks"),
    ]

    @classmethod
    def evaluate(
        cls,
        scan_id: UUID,
        profile: ScanProfile,
        findings: List[FindingResponse],
        scan_plan: Optional[ScanPlanSchema] = None,
        passive_executed: bool = True,
        active_analyzers_executed: Optional[List[str]] = None,
        urls_crawled: int = 0,
    ) -> SecurityCoverageReportSchema:
        active_set = set(active_analyzers_executed or [])
        is_passive_only = profile in (
            ScanProfile.PASSIVE_DISCOVERY,
            ScanProfile.PASSIVE_ONLY,
            ScanProfile.QUICK_ASSESSMENT,
            ScanProfile.SAFE_MODE,
        )

        # Count findings per normalized category
        findings_by_cat: Dict[str, int] = {}
        inconclusive_cats: Set[str] = set()
        for f in findings:
            cat = f.intelligence.vulnerability_category if f.intelligence else "OTHER"
            findings_by_cat[cat] = findings_by_cat.get(cat, 0) + 1
            if f.intelligence and f.intelligence.validation_state.value == "INCONCLUSIVE":
                inconclusive_cats.add(cat)

        entries: List[OWASPCoverageEntrySchema] = []
        gaps: List[str] = []

        counts = {
            CoverageStatus.TESTED: 0,
            CoverageStatus.PARTIAL: 0,
            CoverageStatus.SKIPPED: 0,
            CoverageStatus.UNTESTED: 0,
            CoverageStatus.INCONCLUSIVE: 0,
        }

        for owasp_id, owasp_name, mapped_cats, desc in cls.OWASP_2021_CATALOG:
            detected_count = sum(findings_by_cat.get(c, 0) for c in mapped_cats)
            executed: List[str] = []
            skipped: List[str] = []

            if urls_crawled == 0 and not findings:
                status = CoverageStatus.INCONCLUSIVE
                explanation = "Zero URLs successfully crawled (target unreachable or ScopeGate blocked); coverage cannot be established."
                gaps.append(f"{owasp_id} ({owasp_name}): target not crawled.")
            elif owasp_id == "A09:2021":
                status = CoverageStatus.UNTESTED
                skipped.append("internal_log_monitoring_audit")
                explanation = "Server-side logging and alerting adequacy cannot be verified via external DAST."
                gaps.append(f"{owasp_id} ({owasp_name}): requires internal logging/SIEM review.")
            elif owasp_id == "A06:2021":
                status = CoverageStatus.PARTIAL if passive_executed else CoverageStatus.UNTESTED
                if passive_executed:
                    executed.append("passive_technology_fingerprinting")
                skipped.append("sca_dependency_manifest_audit")
                explanation = "Technology banners observed passively, but full dependency vulnerability scanning (SCA) was not executed."
                gaps.append(f"{owasp_id} ({owasp_name}): requires SCA / SBOM dependency scanning.")
            elif owasp_id == "A08:2021":
                status = CoverageStatus.PARTIAL if passive_executed else CoverageStatus.UNTESTED
                if passive_executed:
                    executed.append("PASSIVE-HTML-SRI-MISSING")
                skipped.append("artifact_signature_deserialization_audit")
                explanation = "Checked external script SRI attributes passively; code signing and deserialization require white-box/SAST review."
            elif owasp_id == "A03:2021":
                req_active = {"ACT-SQLI-ANALYZER", "ACT-XSS-ANALYZER", "ACT-MISCONFIG-ANALYZER"}
                ran = sorted(req_active & active_set)
                not_ran = sorted(req_active - active_set)
                executed.extend(ran)
                skipped.extend(not_ran)
                if is_passive_only or not ran:
                    status = CoverageStatus.SKIPPED
                    explanation = f"Active injection checks skipped under profile '{profile.value}'."
                    gaps.append(f"{owasp_id} ({owasp_name}): active injection checks skipped ({profile.value}).")
                elif mapped_cats & inconclusive_cats and detected_count == len(mapped_cats & inconclusive_cats):
                    status = CoverageStatus.INCONCLUSIVE
                    explanation = "Injection probes executed, but results remain inconclusive and need manual review."
                elif len(ran) == len(req_active):
                    status = CoverageStatus.TESTED
                    explanation = f"Executed bounded non-destructive active checks: {', '.join(ran)}."
                else:
                    status = CoverageStatus.PARTIAL
                    explanation = f"Executed {', '.join(ran)}; skipped {', '.join(not_ran)} due to profile/module constraints."
            elif owasp_id == "A10:2021":
                if "ACT-SSRF-ANALYZER" in active_set:
                    executed.append("ACT-SSRF-ANALYZER")
                    status = CoverageStatus.TESTED
                    explanation = "Executed safe ScopeGate-bounded SSRF candidate analysis."
                else:
                    skipped.append("ACT-SSRF-ANALYZER")
                    status = CoverageStatus.SKIPPED
                    explanation = f"Active SSRF analyzer skipped under profile '{profile.value}' or module filter."
                    gaps.append(f"{owasp_id} ({owasp_name}): active SSRF probe not executed.")
            elif owasp_id in ("A01:2021", "A02:2021", "A04:2021", "A05:2021", "A07:2021"):
                if passive_executed:
                    executed.append("passive_http_analysis")
                if owasp_id == "A01:2021" and "ACT-TRAVERSAL-ANALYZER" in active_set:
                    executed.append("ACT-TRAVERSAL-ANALYZER")
                if owasp_id in ("A01:2021", "A05:2021") and "ACT-API-SEC-ANALYZER" in active_set:
                    executed.append("ACT-API-SEC-ANALYZER")
                if owasp_id == "A05:2021" and "ACT-MISCONFIG-ANALYZER" in active_set:
                    executed.append("ACT-MISCONFIG-ANALYZER")
                if owasp_id == "A05:2021" and "ACT-XXE-ANALYZER" in active_set:
                    executed.append("ACT-XXE-ANALYZER")
                if owasp_id == "A07:2021" and "ACT-AUTH-ANALYZER" in active_set:
                    executed.append("ACT-AUTH-ANALYZER")

                if owasp_id == "A04:2021":
                    status = CoverageStatus.PARTIAL
                    skipped.append("threat_modeling_design_review")
                    explanation = "Clickjacking & passive design headers verified; architectural threat design requires manual review."
                elif executed:
                    status = CoverageStatus.TESTED if (not is_passive_only or owasp_id == "A02:2021") else CoverageStatus.PARTIAL
                    explanation = desc
                else:
                    status = CoverageStatus.UNTESTED
                    explanation = "No matching passive or active checks executed."

            counts[status] += 1
            entries.append(OWASPCoverageEntrySchema(
                owasp_id=owasp_id,
                owasp_name=owasp_name,
                status=status,
                checks_executed=executed,
                checks_skipped=skipped,
                findings_detected=detected_count,
                explanation=explanation,
            ))

        # Weighted DAST coverage: TESTED = 1.0, PARTIAL = 0.5, others = 0.0
        total_cats = len(entries)
        weighted = counts[CoverageStatus.TESTED] * 1.0 + counts[CoverageStatus.PARTIAL] * 0.5
        pct = round((weighted / total_cats) * 100.0, 1) if total_cats > 0 else 0.0

        return SecurityCoverageReportSchema(
            scan_id=scan_id,
            profile=profile,
            overall_dast_coverage_percent=pct,
            tested_categories_count=counts[CoverageStatus.TESTED],
            partial_categories_count=counts[CoverageStatus.PARTIAL],
            skipped_categories_count=counts[CoverageStatus.SKIPPED],
            untested_categories_count=counts[CoverageStatus.UNTESTED],
            inconclusive_categories_count=counts[CoverageStatus.INCONCLUSIVE],
            owasp_categories=entries,
            coverage_gaps=gaps,
        )
