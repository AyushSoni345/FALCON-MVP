from typing import Final

# Dashboard Modes
DASHBOARD_MODE_LIVE: Final[str] = "Live"
DASHBOARD_MODE_HISTORICAL: Final[str] = "Historical"
DASHBOARD_MODE_INVESTIGATION: Final[str] = "Investigation"

ALLOWED_DASHBOARD_MODES: Final[set[str]] = {
    DASHBOARD_MODE_LIVE,
    DASHBOARD_MODE_HISTORICAL,
    DASHBOARD_MODE_INVESTIGATION
}

# Roles
ROLE_SOC_ANALYST: Final[str] = "SOC Analyst"
ROLE_FRAUD_ANALYST: Final[str] = "Fraud Analyst"
ROLE_INCIDENT_RESPONSE: Final[str] = "Incident Response"
ROLE_SOC_MANAGER: Final[str] = "SOC Manager"
ROLE_EXECUTIVE: Final[str] = "Executive"
ROLE_ADMINISTRATOR: Final[str] = "Administrator"

ALLOWED_ROLES: Final[set[str]] = {
    ROLE_SOC_ANALYST,
    ROLE_FRAUD_ANALYST,
    ROLE_INCIDENT_RESPONSE,
    ROLE_SOC_MANAGER,
    ROLE_EXECUTIVE,
    ROLE_ADMINISTRATOR
}
