from pydantic import BaseModel, Field
from app.models.dashboard import (
    DashboardInformation,
    LiveOperationsConsole,
    IncidentMonitoringWorkspace,
    SecurityKnowledgeGraphVisualizer,
    ExplainableThreatIntelligenceWorkspace,
    ResponseOperationsWorkspace,
    ContinuousLearningWorkspace,
    ExecutiveOperationalAnalytics,
    AnalystInteractionWorkspace,
    ReferencedIncidentResponseLearningPackage
)

class SecurityOperationsDashboard(BaseModel):
    dashboard_information: DashboardInformation = Field(..., description="Workspace 1: Metadata on session")
    live_operations_console: LiveOperationsConsole = Field(..., description="Workspace 2: Overall live metrics")
    incident_monitoring_workspace: IncidentMonitoringWorkspace = Field(..., description="Workspace 3: Incident list & details")
    security_knowledge_graph_visualizer: SecurityKnowledgeGraphVisualizer = Field(..., description="Workspace 4: Graph rendering details")
    explainable_threat_intelligence_workspace: ExplainableThreatIntelligenceWorkspace = Field(..., description="Workspace 5: Threat explainability report")
    response_operations_workspace: ResponseOperationsWorkspace = Field(..., description="Workspace 6: Progress of execution playbooks")
    continuous_learning_workspace: ContinuousLearningWorkspace = Field(..., description="Workspace 7: Model metrics & feedback stats")
    executive_operational_analytics: ExecutiveOperationalAnalytics = Field(..., description="Workspace 8: Long-term trends & workload analytics")
    analyst_interaction_workspace: AnalystInteractionWorkspace = Field(..., description="Workspace 9: Operational workflows & annotation forms")
    referenced_incident_response_learning_package: ReferencedIncidentResponseLearningPackage = Field(..., description="Workspace 10: References to raw package inputs")
