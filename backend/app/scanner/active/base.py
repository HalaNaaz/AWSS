from abc import ABC, abstractmethod
from typing import List, Optional
from uuid import UUID

from backend.app.scanner.active.models import ActiveTarget, ActiveFinding, RequestBudgetTracker
from backend.app.scanner.crawler.client import AsyncHTTPClient


class BaseActiveAnalyzer(ABC):
    """Abstract base class for all active vulnerability detection modules."""

    @property
    @abstractmethod
    def analyzer_id(self) -> str:
        """Unique analyzer identifier, e.g. 'ACT-SQLI-ANALYZER'."""
        pass

    @property
    @abstractmethod
    def analyzer_name(self) -> str:
        """Human-readable analyzer name."""
        pass

    @property
    @abstractmethod
    def category(self) -> str:
        """Vulnerability category, e.g. 'Injection', 'Cross-Site Scripting'."""
        pass

    @property
    @abstractmethod
    def supported_rules(self) -> List[str]:
        """List of rule IDs handled by this analyzer."""
        pass

    @property
    def safe_mode_compatible(self) -> bool:
        """Indicates whether this module's checks are non-destructive and safe for SAFE_ACTIVE."""
        return True

    @abstractmethod
    async def check(
        self,
        target: ActiveTarget,
        client: AsyncHTTPClient,
        budget: RequestBudgetTracker,
        scan_id: UUID,
    ) -> List[ActiveFinding]:
        """Executes active vulnerability probes against the target endpoint.
        
        Args:
            target: ActiveTarget holding endpoint metadata, baseline response, and parameters.
            client: Hardened AsyncHTTPClient with ScopeGate validation.
            budget: RequestBudgetTracker enforcing probe limits.
            scan_id: UUID of current assessment.
            
        Returns:
            List of detected ActiveFinding instances.
        """
        pass
