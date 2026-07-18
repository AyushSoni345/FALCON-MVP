class Module4Exception(Exception):
    """Base exception for FALCON Module 4."""
    def __init__(self, message: str):
        super().__init__(message)
        self.message = message

class InvalidSecurityGraphEventException(Module4Exception):
    """Raised when an incoming SecurityGraphEvent fails validation."""
    pass

class CorrelationException(Module4Exception):
    """Raised when correlation fails or runtime exceptions occur during correlation."""
    pass

class GraphTraversalException(Module4Exception):
    """Raised when an error occurs while traversing graph nodes, relationships or paths."""
    pass

class IncidentCreationException(Module4Exception):
    """Raised when there is an issue constructing the CorrelatedSecurityIncident."""
    pass

class EvidenceValidationException(Module4Exception):
    """Raised when evidence verification fails or finds fatal inconsistencies."""
    pass

class PatternRecognitionException(Module4Exception):
    """Raised when pattern matching fails or Encounters unexpected formats."""
    pass

class HypothesisGenerationException(Module4Exception):
    """Raised when generating threat hypotheses fails."""
    pass

class ConfidenceCalculationException(Module4Exception):
    """Raised when calculating multi-dimensional confidence scores fails."""
    pass

class RepositoryException(Module4Exception):
    """Raised when saving, updating, or retrieving incidents from repository fails."""
    pass
