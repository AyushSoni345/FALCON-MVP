from typing import Dict, Any
from fastapi.encoders import jsonable_encoder
from app.schemas.output import SecurityOperationsDashboard

class DashboardFormatter:
    @staticmethod
    def format_dashboard(dashboard: SecurityOperationsDashboard) -> Dict[str, Any]:
        """
        Formats and serializes the dashboard object ensuring a stable JSON layout.
        """
        # jsonable_encoder guarantees datetime strings are ISO 8601 formatted
        # and Pydantic models are mapped recursively to standard Python dicts/lists.
        return jsonable_encoder(dashboard)
