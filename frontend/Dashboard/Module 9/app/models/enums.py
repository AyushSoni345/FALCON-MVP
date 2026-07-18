from enum import Enum

class ReportStatus(str, Enum):
    DRAFT = "Draft"
    FINAL = "Final"

class RiskLevel(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

class DashboardMode(str, Enum):
    LIVE = "Live"
    HISTORICAL = "Historical"
    INVESTIGATION = "Investigation"

class ExecutionStatus(str, Enum):
    PENDING = "Pending"
    RUNNING = "Running"
    COMPLETED = "Completed"
    FAILED = "Failed"

class ValidationStatus(str, Enum):
    APPROVED = "Approved"
    REJECTED = "Rejected"
    PENDING = "Pending"

class IncidentStatus(str, Enum):
    UNDER_INVESTIGATION = "Under Investigation"
    CONTAINED = "Contained"
    CLOSED = "Closed"
    ASSIGNED = "Assigned"
    REOPENED = "Reopened"

class TeamRole(str, Enum):
    SOC = "SOC"
    FRAUD = "Fraud"
    IT = "IT"
    NETWORK = "Network"
