class DashboardException(Exception):
    """Base exception for all Module 9 errors."""
    def __init__(self, message: str, status_code: int = 500):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)

class DashboardNotFoundException(DashboardException):
    """Raised when the requested dashboard session cannot be found."""
    def __init__(self, message: str = "Dashboard not found"):
        super().__init__(message, status_code=404)

class IRLPValidationException(DashboardException):
    """Raised when the incoming IRLP package fails business or reference validation."""
    def __init__(self, message: str):
        super().__init__(message, status_code=422)

class ReferenceConflictException(DashboardException):
    """Raised when there is a mismatch or conflict in referenced IDs."""
    def __init__(self, message: str):
        super().__init__(message, status_code=409)

class InvalidDashboardModeException(DashboardException):
    """Raised when the requested dashboard mode is invalid."""
    def __init__(self, message: str):
        super().__init__(message, status_code=400)
