from abc import ABC, abstractmethod
from typing import Dict, Any

class BaseEnricher(ABC):
    """
    Standard interface for all enrichment components in the threat enrichment pipeline.
    """

    @abstractmethod
    def enrich(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Processes and adds context to the event dictionary.
        """
        pass
