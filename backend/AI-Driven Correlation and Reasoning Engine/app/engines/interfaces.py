from abc import ABC, abstractmethod
from typing import Any, Dict, List
from module4.app.models.models import SecurityGraphEvent, CorrelatedSecurityIncident, ThreatHypothesis

class BaseTemporalCorrelationEngine(ABC):
    @abstractmethod
    def correlate(self, events: List[SecurityGraphEvent]) -> Dict[str, Any]:
        """
        Analyze timestamps and reconstruct chronological order/dependencies.
        """
        pass

class BaseGraphReasoningEngine(ABC):
    @abstractmethod
    def reason(self, events: List[SecurityGraphEvent], temporal_output: Dict[str, Any]) -> Dict[str, Any]:
        """
        Reason over graph topology, paths, relationships, and shared entities.
        """
        pass

class BasePatternRecognitionEngine(ABC):
    @abstractmethod
    def recognize(
        self,
        events: List[SecurityGraphEvent],
        temporal_output: Dict[str, Any],
        graph_output: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Detect known attack and fraud patterns (e.g. Account Takeover, Credential Theft).
        """
        pass

class BaseAttackSequenceEngine(ABC):
    @abstractmethod
    def reconstruct(
        self,
        events: List[SecurityGraphEvent],
        temporal_output: Dict[str, Any],
        graph_output: Dict[str, Any],
        patterns_output: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Reconstruct complete, ordered attack timelines with entries and exits.
        """
        pass

class BaseEvidenceValidator(ABC):
    @abstractmethod
    def validate_evidence(
        self,
        events: List[SecurityGraphEvent],
        sequence_output: Dict[str, Any],
        graph_output: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Validate available supporting and contradictory evidence.
        """
        pass

class BaseHypothesisGenerator(ABC):
    @abstractmethod
    def generate_hypotheses(
        self,
        events: List[SecurityGraphEvent],
        evidence_output: Dict[str, Any]
    ) -> List[ThreatHypothesis]:
        """
        Generate and rank plausible explanations for the observed activity.
        """
        pass

class BaseConfidenceScoringEngine(ABC):
    @abstractmethod
    def calculate_confidence(
        self,
        events: List[SecurityGraphEvent],
        evidence_output: Dict[str, Any],
        hypotheses: List[ThreatHypothesis]
    ) -> Dict[str, Any]:
        """
        Determine multi-dimensional confidence and uncertainty metrics.
        """
        pass

class BaseIncidentBuilder(ABC):
    @abstractmethod
    def build_incident(
        self,
        events: List[SecurityGraphEvent],
        temporal_output: Dict[str, Any],
        graph_output: Dict[str, Any],
        patterns_output: Dict[str, Any],
        sequence_output: Dict[str, Any],
        evidence_output: Dict[str, Any],
        hypotheses: List[ThreatHypothesis],
        confidence_output: Dict[str, Any]
    ) -> CorrelatedSecurityIncident:
        """
        Assemble final CorrelatedSecurityIncident container.
        """
        pass

class BasePredictiveReasoningEngine(ABC):
    @abstractmethod
    def predict(
        self,
        events: List[SecurityGraphEvent],
        sequence_output: Dict[str, Any],
        confidence_output: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Placeholder/Interface for future threat forecasting capabilities.
        """
        pass
