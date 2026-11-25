from typing import List, Dict, Optional, Set
from urllib.parse import urlparse

from shared.schemas.discovery import (
    DiscoveredEndpointCreate,
    ParameterIntelligenceSchema,
    ParameterCategory,
    PriorityLevel,
    PrioritizedEndpointSchema
)


class DiscoveryPrioritizationEngine:
    """Evidence-based attack surface exploration prioritizer.
    
    Computes an exploration priority score (0-100) based on observable structural signals
    such as authentication requirements, file uploads, redirect parameters, dynamic APIs,
    and attached findings.
    
    CRITICAL DISTINCTION: This score indicates recommended pentesting or scanning priority;
    it is strictly distinct from vulnerability severity (CVSS).
    """

    AUTH_KEYWORDS = {"login", "signin", "auth", "oauth", "token", "session", "admin", "dashboard", "account"}
    FILE_KEYWORDS = {"upload", "download", "file", "document", "attachment", "import", "export"}
    REDIRECT_KEYWORDS = {"redirect", "url", "return", "next", "target", "dest"}

    @classmethod
    def prioritize_endpoint(
        cls,
        endpoint: DiscoveredEndpointCreate,
        parameters: Optional[List[ParameterIntelligenceSchema]] = None,
        has_form: bool = False,
        findings_count: int = 0
    ) -> PrioritizedEndpointSchema:
        """Calculates the exploration priority score and assigns risk signals."""
        score = 0.0
        signals: List[str] = []
        path = urlparse(endpoint.normalized_url).path.lower()
        method = endpoint.method.upper()

        auth_required = False
        has_params = bool(endpoint.query_params or parameters)

        # 1. Authentication / Sensitive Route Signals
        if endpoint.status_code in (401, 403) or any(k in path for k in cls.AUTH_KEYWORDS):
            score += 25.0
            auth_required = True
            signals.append("Authentication boundary or sensitive route (+25)")

        # 2. File Handling / Upload Signals
        if any(k in path for k in cls.FILE_KEYWORDS) or (parameters and any(p.category == ParameterCategory.FILE for p in parameters)):
            score += 20.0
            signals.append("File upload / file handling capability (+20)")

        # 3. Redirect / SSRF Risk Parameters
        if parameters and any(p.category == ParameterCategory.REDIRECT for p in parameters):
            score += 15.0
            signals.append("Redirect / URL destination parameter present (+15)")

        # 4. High-Risk Injection Parameters (SQLi/XSS/Command Injection Candidates)
        if parameters and any(p.category in (ParameterCategory.IDENTIFIER, ParameterCategory.SEARCH) for p in parameters):
            score += 15.0
            signals.append("High-risk query parameter (Identifier/Search candidate) (+15)")

        # 5. Form Target
        if has_form or method in ("POST", "PUT", "PATCH"):
            score += 10.0
            signals.append("State-mutating method or form submission target (+10)")

        # 6. Dynamic API Endpoint
        if any(api_token in path for api_token in ("/api/", "/rest/", "/graphql", "/v1/", "/v2/")):
            score += 10.0
            signals.append("Structured API endpoint (+10)")

        # 7. Associated Findings
        if findings_count > 0:
            score += min(25.0, findings_count * 10.0)
            signals.append(f"Associated security findings present ({findings_count}) (+{min(25, findings_count * 10)})")

        # 8. Status Code Anomaly
        if endpoint.status_code and endpoint.status_code >= 400:
            score += 5.0
            signals.append(f"HTTP error status code observed ({endpoint.status_code}) (+5)")

        # Clamp score between 0.0 and 100.0
        clamped_score = min(100.0, max(0.0, score))

        # Assign level
        if clamped_score >= 60.0:
            level = PriorityLevel.HIGH
        elif clamped_score >= 30.0:
            level = PriorityLevel.MEDIUM
        else:
            level = PriorityLevel.LOW

        return PrioritizedEndpointSchema(
            url=endpoint.normalized_url,
            method=method,
            priority_score=round(clamped_score, 1),
            priority_level=level,
            risk_signals=signals,
            auth_required=auth_required,
            has_parameters=has_params,
            findings_count=findings_count
        )

    @classmethod
    def prioritize_all(
        cls,
        endpoints: List[DiscoveredEndpointCreate],
        parameters_by_url: Optional[Dict[str, List[ParameterIntelligenceSchema]]] = None,
        forms_by_action: Optional[Dict[str, bool]] = None,
        findings_by_url: Optional[Dict[str, int]] = None
    ) -> List[PrioritizedEndpointSchema]:
        """Prioritizes a collection of endpoints and returns them sorted by priority score descending."""
        params_map = parameters_by_url or {}
        forms_map = forms_by_action or {}
        findings_map = findings_by_url or {}

        results: List[PrioritizedEndpointSchema] = []
        for ep in endpoints:
            url = ep.normalized_url
            ep_params = params_map.get(url, [])
            has_form = forms_map.get(url, False)
            findings_count = findings_map.get(url, 0)

            prioritized = cls.prioritize_endpoint(
                endpoint=ep,
                parameters=ep_params,
                has_form=has_form,
                findings_count=findings_count
            )
            results.append(prioritized)

        # Sort descending by priority score
        results.sort(key=lambda x: x.priority_score, reverse=True)
        return results
