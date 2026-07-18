from abc import ABC, abstractmethod
from typing import List
from module5.models.input.incident import CorrelatedSecurityIncident
from module5.models.shared.engine_result import EngineResult

class BaseAnalyticsEngine(ABC):
    """
    Abstract Base Class that all Module 5 AI Analytics Engines must implement.
    """
    @property
    @abstractmethod
    def engine_name(self) -> str:
        """
        Returns the unique name of this analytics engine.
        """
        pass

    @abstractmethod
    async def analyze(
        self, 
        incident: CorrelatedSecurityIncident, 
        external_signals: List[str]
    ) -> EngineResult:
        """
        Analyzes the immutable CorrelatedSecurityIncident, incorporating any shared signals.
        Returns a standard EngineResult object.
        """
        pass
