class InvalidRiskAssessmentException(Exception):
    """
    Raised when the incoming UnifiedRiskAssessment fails validation checks.
    """
    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)

class ReportGenerationException(Exception):
    """
    Raised when the report generation pipeline encounters an error.
    """
    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)
