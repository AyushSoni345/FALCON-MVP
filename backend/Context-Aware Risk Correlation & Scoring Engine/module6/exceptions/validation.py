"""Validation exceptions."""

class ValidationException(Exception):
    """Raised when DomainAIAssessment schema is violated, or fields are out of bounds."""
    pass

class ContextCompletenessException(Exception):
    """Raised if critical required keys are entirely missing and no defaults exist."""
    pass
