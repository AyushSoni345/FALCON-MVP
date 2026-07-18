from datetime import UTC, datetime
import uuid
import logging
from typing import Dict, Optional, List
from app.exceptions.exceptions import DashboardNotFoundException, InvalidDashboardModeException
from app.schemas.input import IncidentResponseLearningPackage, AnalystValidation
from app.schemas.output import SecurityOperationsDashboard
from app.services.dashboard_builder import DashboardBuilder
from app.models.dashboard import CommentObject
from app.models.enums import DashboardMode, IncidentStatus

logger = logging.getLogger("FALCON.Module9.DashboardManager")

class DashboardManager:
    def __init__(self):
        # Maps dashboard_id to SecurityOperationsDashboard
        self.active_sessions: Dict[str, SecurityOperationsDashboard] = {}
        # Stores the original package referenced per session for refresh purposes
        self.session_packages: Dict[str, IncidentResponseLearningPackage] = {}

    def load_dashboard(
        self,
        package: IncidentResponseLearningPackage,
        mode: DashboardMode = DashboardMode.LIVE,
        refresh_interval: int = 30
    ) -> SecurityOperationsDashboard:
        """
        Validates, initializes session, and returns compiled SecurityOperationsDashboard.
        """
        dashboard_id = str(uuid.uuid4())
        logger.info(f"Initializing dashboard session {dashboard_id} with mode {mode}")

        dashboard = DashboardBuilder.build_dashboard(
            package=package,
            dashboard_id=dashboard_id,
            mode=mode,
            refresh_interval=refresh_interval
        )

        self.active_sessions[dashboard_id] = dashboard
        self.session_packages[dashboard_id] = package

        logger.info(f"Dashboard session {dashboard_id} loaded successfully.")
        return dashboard

    def get_dashboard(self, dashboard_id: str) -> SecurityOperationsDashboard:
        """
        Retrieves the active dashboard session. Raises DashboardNotFoundException if missing.
        """
        if dashboard_id not in self.active_sessions:
            raise DashboardNotFoundException(f"Dashboard session '{dashboard_id}' not found.")
        return self.active_sessions[dashboard_id]

    def refresh_dashboard(self, dashboard_id: str) -> SecurityOperationsDashboard:
        """
        Updates only dashboard visualization parameters (timestamp, progress update simulation).
        Does not rerun AI or regenerate responses.
        """
        if dashboard_id not in self.active_sessions:
            raise DashboardNotFoundException(f"Dashboard session '{dashboard_id}' not found.")

        logger.info(f"Refreshing visualization state for session {dashboard_id}")
        dashboard = self.active_sessions[dashboard_id]
        package = self.session_packages[dashboard_id]

        # Simulation: slightly update progress on refresh to demonstrate active monitoring
        current_progress = dashboard.incident_monitoring_workspace.response_progress
        new_progress = min(1.0, current_progress + 0.05) if current_progress < 1.0 else 1.0

        # Build refreshed dashboard
        refreshed = DashboardBuilder.build_dashboard(
            package=package,
            dashboard_id=dashboard_id,
            mode=dashboard.dashboard_information.dashboard_mode,
            refresh_interval=dashboard.dashboard_information.refresh_interval
        )

        # Carry over analyst comments and tags from the active state to preserve edits
        refreshed.analyst_interaction_workspace.analyst_comments = dashboard.analyst_interaction_workspace.analyst_comments
        refreshed.analyst_interaction_workspace.incident_tags = dashboard.analyst_interaction_workspace.incident_tags
        refreshed.analyst_interaction_workspace.audit_annotations = dashboard.analyst_interaction_workspace.audit_annotations

        # Apply progress update
        refreshed.incident_monitoring_workspace.response_progress = new_progress
        refreshed.response_operations_workspace.recovery_progress = new_progress
        if new_progress >= 0.7:
            refreshed.response_operations_workspace.containment_status = "Contained"

        self.active_sessions[dashboard_id] = refreshed
        return refreshed

    def add_comment(self, dashboard_id: str, author: str, text: str) -> CommentObject:
        """
        Appends analyst comment to the analyst interaction workspace.
        """
        dashboard = self.get_dashboard(dashboard_id)
        comment_id = f"c-{uuid.uuid4().hex[:6]}"
        comment = CommentObject(
            comment_id=comment_id,
            author=author,
            text=text,
            timestamp=datetime.now(UTC)
        )
        dashboard.analyst_interaction_workspace.analyst_comments.append(comment)
        
        # Log action to audit annotation trail
        dashboard.analyst_interaction_workspace.audit_annotations.append({
            "action": "Comment Added",
            "actor": author,
            "timestamp": datetime.now(UTC),
            "notes": f"Comment {comment_id} appended."
        })
        
        return comment

    def perform_workflow_action(self, dashboard_id: str, action: str, actor: str) -> IncidentStatus:
        """
        Updates the incident workflow status (Assign, Close, Reopen).
        """
        dashboard = self.get_dashboard(dashboard_id)
        if action not in dashboard.analyst_interaction_workspace.workflow_actions:
            raise ValueError(f"Workflow action '{action}' is not allowed. Choose from: {dashboard.analyst_interaction_workspace.workflow_actions}")

        new_status = IncidentStatus.UNDER_INVESTIGATION
        if action == "Close":
            new_status = IncidentStatus.CLOSED
        elif action == "Reopen":
            new_status = IncidentStatus.REOPENED
        elif action == "Assign":
            new_status = IncidentStatus.ASSIGNED

        dashboard.live_operations_console.package_status = new_status.value
        dashboard.incident_monitoring_workspace.selected_incident.package_status = new_status.value

        # Mock Analyst Validation if close or assign occurs
        if dashboard.analyst_interaction_workspace.analyst_validation is None:
            validation = AnalystValidation(
                analyst_decision=action,
                validation_notes=f"Updated status via analyst action: {action}",
                override_reason=None,
                approval_timestamp=datetime.now(UTC)
            )
            dashboard.analyst_interaction_workspace.analyst_validation = validation
            dashboard.response_operations_workspace.analyst_validation = validation

        # Add audit entry
        dashboard.analyst_interaction_workspace.audit_annotations.append({
            "action": f"Workflow {action}",
            "actor": actor,
            "timestamp": datetime.now(UTC),
            "notes": f"Incident status changed to {new_status.value}."
        })
        
        return new_status
