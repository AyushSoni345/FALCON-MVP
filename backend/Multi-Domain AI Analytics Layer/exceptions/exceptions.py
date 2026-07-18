class InvalidIncidentException(Exception):
    """
    Raised when the input CorrelatedSecurityIncident fails validation checks.
    """
    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)

class AnalyticsPipelineException(Exception):
    """
    Raised when the orchestration or fusion logic encounters an unrecoverable failure.
    """
    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)
