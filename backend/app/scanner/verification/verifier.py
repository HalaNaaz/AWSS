from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, Tuple
from shared.schemas.common import FindingStatus


class BaseVerificationPlugin(ABC):
    """Abstract base class for second-order deterministic verification plugins."""

    @property
    @abstractmethod
    def vulnerability_type(self) -> str:
        """The vulnerability class handled, e.g. 'SQL_INJECTION', 'XSS', 'SSRF'."""
        pass

    @abstractmethod
    async def verify(self, finding_data: Dict[str, Any]) -> Tuple[FindingStatus, Optional[Dict[str, Any]]]:
        """Executes secondary deterministic verification probe.
        
        Returns:
            Tuple of (FindingStatus, secondary_evidence_dict or None)
        """
        pass
