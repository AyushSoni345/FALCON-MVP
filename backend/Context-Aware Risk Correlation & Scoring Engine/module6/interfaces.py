from abc import ABC, abstractmethod
from typing import Dict, Any, Tuple, Optional
from module6.schemas.domain_ai_assessment import DomainAIAssessment
from module6.schemas.unified_risk_assessment import ContextEvaluation
from module6.schemas.decision_trace import DecisionTrace

class IContextLoader(ABC):
    @abstractmethod
    def load_context(self, assessment: DomainAIAssessment, external_context: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Loads context information from input, mock DBs, and config defaults based on entity identifiers."""
        pass

class IContextNormalizer(ABC):
    @abstractmethod
    def normalize(self, raw_context: Dict[str, Any]) -> Dict[str, Any]:
        """Maps varying naming structures and values to standard schema forms (e.g. HNW -> High Net Worth)."""
        pass

class IContextEvaluator(ABC):
    @abstractmethod
    def evaluate(self, normalized_context: Dict[str, Any]) -> Tuple[ContextEvaluation, float]:
        """Returns the fully structured ContextEvaluation and its completeness score."""
        pass

class IRiskScoringPipeline(ABC):
    @abstractmethod
    def calculate_scores(self, active_domains: Dict[str, Any], context: ContextEvaluation) -> Tuple[Dict[str, float], float, Dict[str, Any]]:
        """Calculates weighted domain scores, final unified score, and gathers math trace details."""
        pass

class IConfidenceFusion(ABC):
    @abstractmethod
    def calculate_confidence(self, ai_confidence: float, context_completeness: float, active_domains: Dict[str, Any]) -> Tuple[float, Dict[str, Any]]:
        """Fuses AI and context metrics to derive overall decision confidence and metadata.
        Returns: (overall_confidence, fusion_trace)
        """
        pass

class ISuppressionEngine(ABC):
    @abstractmethod
    def evaluate_suppression(self, scores: Dict[str, float], context: ContextEvaluation, active_domains_count: int, correlation_strength: float) -> Tuple[bool, Optional[str], Optional[str], Dict[str, Any]]:
        """Determines if the incident should be suppressed, returning suppression state, rule name, reason, and trace."""
        pass

class IPrioritizationEngine(ABC):
    @abstractmethod
    def evaluate_priority(self, unified_score: float, context: ContextEvaluation, suppressed: bool) -> Tuple[str, Dict[str, Any]]:
        """Determines the final priority (P1-P4) and return priority logic trace."""
        pass

class IDecisionTraceRepository(ABC):
    @abstractmethod
    def save(self, trace: DecisionTrace) -> None:
        """Persists the DecisionTrace details to durable storage."""
        pass

    @abstractmethod
    def get_by_id(self, trace_id: str) -> Optional[DecisionTrace]:
        """Retrieves a previously stored trace."""
        pass

    @abstractmethod
    def get_by_idempotency_key(self, idempotency_key: str) -> Optional[DecisionTrace]:
        """Retrieves a trace matching the unique idempotency key (hash)."""
        pass
