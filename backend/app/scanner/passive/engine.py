from typing import List, Dict, Any, Optional, Set, Tuple
from uuid import UUID

from backend.app.core.logging import logger
from backend.app.scanner.passive.base import BasePassiveAnalyzer
from backend.app.scanner.passive.models import HTTPResponseContext, PassiveFinding
from backend.app.scanner.passive.analyzers.headers import SecurityHeaderAnalyzer
from backend.app.scanner.passive.analyzers.cookies import CookieSecurityAnalyzer
from backend.app.scanner.passive.analyzers.cors import CORSAnalyzer
from backend.app.scanner.passive.analyzers.disclosure import InformationDisclosureAnalyzer
from backend.app.scanner.passive.analyzers.https_config import HTTPSConfigAnalyzer
from backend.app.scanner.passive.analyzers.html_security import HTMLSecurityAnalyzer


class PassiveAnalysisEngine:
    """Master Coordinator and execution engine for passive HTTP security analysis."""

    def __init__(self, analyzers: Optional[List[BasePassiveAnalyzer]] = None):
        self._analyzers: List[BasePassiveAnalyzer] = analyzers or [
            SecurityHeaderAnalyzer(),
            CookieSecurityAnalyzer(),
            CORSAnalyzer(),
            InformationDisclosureAnalyzer(),
            HTTPSConfigAnalyzer(),
            HTMLSecurityAnalyzer()
        ]

    def register_analyzer(self, analyzer: BasePassiveAnalyzer) -> None:
        """Registers a custom or extended passive analyzer."""
        self._analyzers.append(analyzer)

    def list_analyzers(self) -> List[Dict[str, Any]]:
        """Returns metadata for all registered passive analyzers."""
        return [
            {
                "analyzer_id": a.analyzer_id,
                "name": a.analyzer_name,
                "category": a.category,
                "supported_rules_count": len(a.supported_rules),
                "supported_rules": a.supported_rules
            }
            for a in self._analyzers
        ]

    def list_all_rules(self) -> List[str]:
        """Returns a flat list of all supported rule identifiers across analyzers."""
        rules: List[str] = []
        for a in self._analyzers:
            rules.extend(a.supported_rules)
        return rules

    def analyze_response(
        self,
        context: HTTPResponseContext,
        enabled_rule_ids: Optional[Set[str]] = None
    ) -> List[PassiveFinding]:
        """Executes all registered analyzers against a single observed HTTP transaction.
        
        Args:
            context: Observed request/response context.
            enabled_rule_ids: Optional set of rule IDs to filter execution.
            
        Returns:
            List of unique, evidence-sealed PassiveFinding objects.
        """
        all_findings: List[PassiveFinding] = []
        seen_keys: Set[Tuple[str, str, Optional[str]]] = set()

        for analyzer in self._analyzers:
            try:
                analyzer_findings = analyzer.analyze(context)
                for f in analyzer_findings:
                    if enabled_rule_ids and f.rule_id not in enabled_rule_ids:
                        continue

                    # Deduplication key: (rule_id, normalized_url, parameter)
                    dedup_key = (f.rule_id, f.url, f.parameter)
                    if dedup_key not in seen_keys:
                        seen_keys.add(dedup_key)
                        if not f.evidence_hash:
                            f.seal_evidence()
                        all_findings.append(f)
            except Exception as exc:
                logger.error(f"[PassiveAnalysisEngine] Analyzer '{analyzer.analyzer_id}' error on {context.url}: {str(exc)}")

        return all_findings

    def analyze_batch(
        self,
        contexts: List[HTTPResponseContext],
        enabled_rule_ids: Optional[Set[str]] = None
    ) -> List[PassiveFinding]:
        """Executes passive analysis across a batch of HTTP transactions."""
        batch_findings: List[PassiveFinding] = []
        seen_keys: Set[Tuple[str, str, Optional[str]]] = set()

        for ctx in contexts:
            findings = self.analyze_response(ctx, enabled_rule_ids=enabled_rule_ids)
            for f in findings:
                dedup_key = (f.rule_id, f.url, f.parameter)
                if dedup_key not in seen_keys:
                    seen_keys.add(dedup_key)
                    batch_findings.append(f)

        return batch_findings
