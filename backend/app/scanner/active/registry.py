from typing import Dict, List, Optional, Set, Any
from backend.app.scanner.active.base import BaseActiveAnalyzer
from backend.app.scanner.active.analyzers import (
    SQLInjectionAnalyzer,
    XSSAnalyzer,
    MisconfigurationAnalyzer,
    SSRFAnalyzer,
    XXEAnalyzer,
    AuthenticationAnalyzer,
)
from shared.schemas.common import ScanProfile


class ActivePluginRegistry:
    """Central registry managing discovery, retrieval, and profile-based filtering of active security analyzers."""

    def __init__(self, analyzers: Optional[List[BaseActiveAnalyzer]] = None):
        self._analyzers: Dict[str, BaseActiveAnalyzer] = {}
        defaults = analyzers or [
            SQLInjectionAnalyzer(),
            XSSAnalyzer(),
            MisconfigurationAnalyzer(),
            SSRFAnalyzer(),
            XXEAnalyzer(),
            AuthenticationAnalyzer(),
        ]
        for a in defaults:
            self.register(a)

    def register(self, analyzer: BaseActiveAnalyzer) -> None:
        """Registers an active analyzer plugin."""
        self._analyzers[analyzer.analyzer_id] = analyzer

    def get(self, analyzer_id: str) -> Optional[BaseActiveAnalyzer]:
        """Retrieves analyzer by its unique identifier."""
        return self._analyzers.get(analyzer_id)

    def list_analyzers(self) -> List[Dict[str, Any]]:
        """Returns metadata catalogue for all registered active analyzers."""
        return [
            {
                "analyzer_id": a.analyzer_id,
                "name": a.analyzer_name,
                "category": a.category,
                "safe_mode_compatible": a.safe_mode_compatible,
                "supported_rules_count": len(a.supported_rules),
                "supported_rules": a.supported_rules,
            }
            for a in self._analyzers.values()
        ]

    def list_all_rules(self) -> List[str]:
        """Returns flat list of all rule identifiers across all active analyzers."""
        rules: List[str] = []
        for a in self._analyzers.values():
            rules.extend(a.supported_rules)
        return rules

    def get_analyzers_for_profile(
        self,
        profile: ScanProfile,
        enabled_modules: Optional[Set[str]] = None,
    ) -> List[BaseActiveAnalyzer]:
        """Resolves the applicable active analyzers based on scan profile and optional module filters."""
        # Passive profiles do not run active analyzers
        if profile in (ScanProfile.PASSIVE_DISCOVERY, ScanProfile.PASSIVE_ONLY, ScanProfile.SAFE_MODE):
            return []

        selected: List[BaseActiveAnalyzer] = []
        for a in self._analyzers.values():
            # If explicit module filter provided, check filter
            if enabled_modules and a.analyzer_id not in enabled_modules and a.category not in enabled_modules:
                continue

            if profile == ScanProfile.SAFE_ACTIVE:
                if a.safe_mode_compatible:
                    selected.append(a)
            else:
                # STANDARD_ACTIVE, FULL_ASSESSMENT, API_TARGETED
                selected.append(a)

        return selected


# Singleton global registry instance
active_plugin_registry = ActivePluginRegistry()
