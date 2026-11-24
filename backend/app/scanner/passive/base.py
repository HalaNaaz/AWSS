from abc import ABC, abstractmethod
from typing import List
from backend.app.scanner.passive.models import HTTPResponseContext, PassiveFinding


class BasePassiveAnalyzer(ABC):
    """Abstract base class for all passive security check modules."""

    @property
    @abstractmethod
    def analyzer_id(self) -> str:
        """Unique analyzer identifier, e.g. 'SEC-HDR-ANALYZER'."""
        pass

    @property
    @abstractmethod
    def analyzer_name(self) -> str:
        """Human-readable analyzer name."""
        pass

    @property
    @abstractmethod
    def category(self) -> str:
        """Security category, e.g. 'Security Headers', 'Cookies', 'CORS'."""
        pass

    @property
    @abstractmethod
    def supported_rules(self) -> List[str]:
        """List of rule IDs handled by this analyzer."""
        pass

    @abstractmethod
    def analyze(self, context: HTTPResponseContext) -> List[PassiveFinding]:
        """Analyzes an HTTP request/response transaction passively without generating new network traffic.
        
        Args:
            context: HTTPResponseContext containing URL, status, headers, cookies, body, and forms.
            
        Returns:
            List of detected PassiveFinding instances.
        """
        pass
