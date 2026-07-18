from enum import Enum

class ReportStatus(str, Enum):
    DRAFT = "Draft"
    FINAL = "Final"

class RiskLevel(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"
