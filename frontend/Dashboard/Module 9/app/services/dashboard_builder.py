from datetime import UTC, datetime
from app.schemas.input import IncidentResponseLearningPackage
from app.schemas.output import SecurityOperationsDashboard
from app.models.enums import DashboardMode
from app.models.dashboard import (
    DashboardInformation,
    LiveOperationsConsole,
    IncidentMonitoringWorkspace,
    IncidentSummary,
    SecurityKnowledgeGraphVisualizer,
    ExplainableThreatIntelligenceWorkspace,
    ResponseOperationsWorkspace,
    ContinuousLearningWorkspace,
    ExecutiveOperationalAnalytics,
    AnalystInteractionWorkspace,
    ReferencedIncidentResponseLearningPackage
)

class DashboardBuilder:
    @staticmethod
    def build_dashboard(
        package: IncidentResponseLearningPackage,
        dashboard_id: str,
        mode: DashboardMode,
        refresh_interval: int = 30
    ) -> SecurityOperationsDashboard:
        """
        Constructs the SecurityOperationsDashboard workspaces by strictly referencing
        Module 8 objects without altering any business logic.
        """
        # Workspace 1: Dashboard Information
        info = DashboardInformation(
            dashboard_id=dashboard_id,
            response_package_id=package.response_package_info.response_package_id,
            dashboard_timestamp=datetime.now(UTC),
            dashboard_version="1.0.0",
            dashboard_mode=mode,
            refresh_interval=refresh_interval
        )

        # Workspace 2: Live Operations Console
        live = LiveOperationsConsole(
            incident_id=package.response_package_info.incident_id,
            package_status=package.response_package_info.package_status,
            incident_type=package.incident_response_plan.incident_type,
            response_strategy=package.incident_response_plan.response_strategy,
            execution_type=package.response_execution_plan.execution_type,
            execution_priority=package.response_execution_plan.execution_priority,
            assigned_team=package.response_execution_plan.assigned_team,
            soar_preparation_status="Prepared" if package.soar_orchestration_tasks else "N/A",
            workflow_stage="Awaiting Analyst Validation" if not package.analyst_validation else "Validated"
        )

        # Incident Summary Helper
        summary = IncidentSummary(
            incident_id=package.response_package_info.incident_id,
            incident_type=package.incident_response_plan.incident_type,
            package_status=package.response_package_info.package_status,
            response_strategy=package.incident_response_plan.response_strategy,
            execution_priority=package.response_execution_plan.execution_priority,
            assigned_team=package.response_execution_plan.assigned_team,
            execution_type=package.response_execution_plan.execution_type,
            estimated_completion_time=package.response_execution_plan.estimated_completion_time,
            response_progress=0.0
        )

        # Workspace 3: Incident Monitoring Workspace
        incidents = IncidentMonitoringWorkspace(
            selected_incident=summary,
            response_progress=0.0
        )

        # Workspace 4: Security Knowledge Graph Visualizer
        graph = SecurityKnowledgeGraphVisualizer(
            graph_reference=package.referenced_threat_report.report_id
        )

        # Workspace 5: Explainable Threat Intelligence Workspace
        report = package.referenced_threat_report
        explain = ExplainableThreatIntelligenceWorkspace(
            report_id=report.report_id,
            executive_summary_reference=report.executive_summary_reference,
            root_cause_reference=report.root_cause_reference,
            evidence_reference=report.evidence_reference,
            investigation_reference=report.investigation_reference,
            analyst_support_reference=report.analyst_support_reference
        )

        # Workspace 6: Response Operations Workspace
        resp_ops = ResponseOperationsWorkspace(
            incident_response_plan=package.incident_response_plan,
            response_execution_plan=package.response_execution_plan,
            soar_orchestration_tasks=package.soar_orchestration_tasks,
            analyst_validation=package.analyst_validation,
            containment_status="Awaiting Containment" if not package.analyst_validation else "Contained",
            recovery_progress=0.0
        )

        # Workspace 7: Continuous Learning Workspace
        learn = ContinuousLearningWorkspace(
            continuous_learning_package=package.continuous_learning_package,
            model_optimization_recommendations=package.model_optimization_recommendations,
            feedback_audit_trail=package.feedback_audit_trail
        )

        # Workspace 8: Executive & Operational Analytics
        analytics = ExecutiveOperationalAnalytics()

        # Workspace 9: Analyst Workspace
        analyst = AnalystInteractionWorkspace(
            analyst_comments=[],
            incident_tags=["AWAITING_REVIEW"],
            workflow_actions=["Assign", "Close", "Reopen"],
            analyst_validation=package.analyst_validation,
            audit_annotations=[]
        )

        # Workspace 10: Traceability References (References only!)
        refs = ReferencedIncidentResponseLearningPackage(
            response_package_id=package.response_package_info.response_package_id,
            incident_response_plan_reference="#/incident_response_plan",
            response_execution_plan_reference="#/response_execution_plan",
            soar_tasks_reference=[task.task_id for task in package.soar_orchestration_tasks],
            analyst_validation_reference="#/analyst_validation" if package.analyst_validation else None,
            continuous_learning_reference="#/continuous_learning_package" if package.continuous_learning_package else None,
            optimization_reference=[f"#/model_optimization_recommendations/{idx}" for idx in range(len(package.model_optimization_recommendations))],
            feedback_reference="#/feedback_audit_trail" if package.feedback_audit_trail else None,
            referenced_threat_report_reference="#/referenced_threat_report"
        )

        return SecurityOperationsDashboard(
            dashboard_information=info,
            live_operations_console=live,
            incident_monitoring_workspace=incidents,
            security_knowledge_graph_visualizer=graph,
            explainable_threat_intelligence_workspace=explain,
            response_operations_workspace=resp_ops,
            continuous_learning_workspace=learn,
            executive_operational_analytics=analytics,
            analyst_interaction_workspace=analyst,
            referenced_incident_response_learning_package=refs
        )
