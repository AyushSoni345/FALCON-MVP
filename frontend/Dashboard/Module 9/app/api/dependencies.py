from app.services.dashboard_manager import DashboardManager

# Instantiate a single global manager to store active dashboard sessions
_manager_instance = DashboardManager()

def get_dashboard_manager() -> DashboardManager:
    return _manager_instance
