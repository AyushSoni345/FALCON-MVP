from module4.app.engines.temporal_correlation import TemporalCorrelationEngine
from module4.app.engines.graph_reasoning import GraphReasoningEngine
from module4.app.engines.pattern_recognition import PatternRecognitionEngine
from module4.app.engines.attack_sequence import AttackSequenceEngine
from module4.app.engines.evidence_validator import EvidenceValidator
from module4.app.engines.hypothesis_generator import HypothesisGenerator
from module4.app.engines.confidence_scoring import ConfidenceScoringEngine
from module4.app.engines.incident_builder import IncidentBuilder
from module4.app.repositories.incident_repository import IncidentRepository

class Container:
    """
    A simple Dependency Injection container managing the singleton instances
    of all engines, validators, and repositories.
    """

    def __init__(self) -> None:
        self.temporal_engine = TemporalCorrelationEngine()
        self.graph_engine = GraphReasoningEngine()
        self.pattern_engine = PatternRecognitionEngine()
        self.attack_sequence_engine = AttackSequenceEngine()
        self.evidence_validator = EvidenceValidator()
        self.hypothesis_generator = HypothesisGenerator()
        self.confidence_engine = ConfidenceScoringEngine()
        self.incident_builder = IncidentBuilder()
        self.incident_repository = IncidentRepository()

# Global DI Container instance
container = Container()
