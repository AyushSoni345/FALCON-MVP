from datetime import datetime
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from app.models.enums import DashboardMode, IncidentStatus
from app.schemas.input import (
    ResponsePackageInfo,
    IncidentResponsePlan,
    ResponseExecutionPlan,
    SOAROrchestrationTask,
    AnalystValidation,
    ContinuousLearningPackage,
    ModelOptimizationRecommendation,
    FeedbackAuditTrail,
    ReferencedThreatReport,
    IncidentResponseLearningPackage
)

class DashboardInformation(BaseModel):
    dashboard_id: str = Field(..., description="Dashboard session ID (UUID)")
    response_package_id: str = Field(..., description="Upstream response package ID (UUID)")
    dashboard_timestamp: datetime = Field(..., description="Dashboard load/creation timestamp")
    dashboard_version: str = Field(..., description="Dashboard schema version")
    dashboard_mode: DashboardMode = Field(..., description="Dashboard mode")
    refresh_interval: int = Field(..., description="UI refresh interval in seconds")

class LiveOperationsConsole(BaseModel):
    incident_id: str = Field(..., description="Current Incident ID")
    package_status: str = Field(..., description="Current Package Status")
    incident_type: str = Field(..., description="Incident Type")
    response_strategy: str = Field(..., description="Response Strategy")
    execution_type: str = Field(..., description="Execution Type")
    execution_priority: str = Field(..., description="Execution Priority")
    assigned_team: str = Field(..., description="Assigned Team")
    soar_preparation_status: str = Field(..., description="Current SOAR Preparation Status")
    workflow_stage: str = Field(..., description="Current Workflow Stage")
    historical_metrics_message: str = Field("Historical operational metrics are unavailable because a single Incident Response & Learning Package is currently loaded.", description="Historical info unavailable message")

class IncidentSummary(BaseModel):
    incident_id: str = Field(..., description="Incident identifier")
    incident_type: str = Field(..., description="Threat classification type")
    package_status: str = Field(..., description="Current Package Status")
    response_strategy: str = Field(..., description="SOP strategy outline")
    execution_priority: str = Field(..., description="Priority level")
    assigned_team: str = Field(..., description="Team currently assigned")
    execution_type: str = Field(..., description="Type of execution flow")
    estimated_completion_time: str = Field(..., description="Estimated completion duration/time")
    response_progress: float = Field(..., description="Progress of the corresponding response execution (0.0 to 1.0)")

class IncidentMonitoringWorkspace(BaseModel):
    selected_incident: IncidentSummary = Field(..., description="Currently selected/active incident in view")
    response_progress: float = Field(..., description="Progress of the corresponding response execution (0.0 to 1.0)")

class SecurityKnowledgeGraphVisualizer(BaseModel):
    message: str = Field("Knowledge Graph reference available. Load referenced graph from Module 3 when available.", description="Message when no graph data is loaded")
    graph_reference: str = Field(..., description="Reference ID to the upstream graph")

class ExplainableThreatIntelligenceWorkspace(BaseModel):
    report_id: str = Field(..., description="Report identifier")
    executive_summary_reference: Any = Field(..., description="Executive summary metrics")
    root_cause_reference: Any = Field(..., description="Root cause metrics")
    evidence_reference: Any = Field(..., description="Evidence counts")
    investigation_reference: Any = Field(..., description="Guidance steps and priority artifacts")
    analyst_support_reference: Any = Field(..., description="Analyst support metrics")

class ResponseOperationsWorkspace(BaseModel):
    incident_response_plan: IncidentResponsePlan = Field(..., description="Response plan metadata")
    response_execution_plan: ResponseExecutionPlan = Field(..., description="Execution steps details")
    soar_orchestration_tasks: List[SOAROrchestrationTask] = Field(..., description="SOAR tasks lists")
    analyst_validation: Optional[AnalystValidation] = Field(None, description="Analyst validation details")
    containment_status: str = Field(..., description="Mitigation status")
    recovery_progress: float = Field(..., description="Progress of the system recovery steps (0.0 to 1.0)")

class ContinuousLearningWorkspace(BaseModel):
    continuous_learning_package: Optional[ContinuousLearningPackage] = Field(None, description="Learning labels and features")
    model_optimization_recommendations: List[ModelOptimizationRecommendation] = Field(default_factory=list, description="Model optimization recommendations list")
    feedback_audit_trail: Optional[List[FeedbackAuditTrail]] = Field(None, description="Feedback audit timeline logs")

class ExecutiveOperationalAnalytics(BaseModel):
    historical_metrics_available: bool = Field(False, description="Whether historical analytics are loaded")
    message: str = Field("Historical metrics unavailable. Metrics will become available after multiple response packages have been processed.", description="Analytic message")

class CommentObject(BaseModel):
    comment_id: str = Field(..., description="Unique comment identifier")
    author: str = Field(..., description="Analyst who posted the comment")
    text: str = Field(..., description="Text content")
    timestamp: datetime = Field(..., description="Posted timestamp")

class AnalystInteractionWorkspace(BaseModel):
    analyst_comments: List[CommentObject] = Field(..., description="Chronological log of notes/comments")
    incident_tags: List[str] = Field(..., description="Tags attached to the incident")
    workflow_actions: List[str] = Field(..., description="Available status transition actions")
    analyst_validation: Optional[AnalystValidation] = Field(None, description="Current validation state")
    audit_annotations: List[Dict[str, Any]] = Field(..., description="Action log of the session changes")

class ReferencedIncidentResponseLearningPackage(BaseModel):
    response_package_id: str = Field(..., description="Traceability reference to response package ID")
    incident_response_plan_reference: str = Field(..., description="Traceability reference path to response plan")
    response_execution_plan_reference: str = Field(..., description="Traceability reference path to execution plan")
    soar_tasks_reference: List[str] = Field(..., description="Traceability reference list of SOAR task IDs")
    analyst_validation_reference: Optional[str] = Field(None, description="Traceability reference path to analyst validation")
    continuous_learning_reference: Optional[str] = Field(None, description="Traceability reference path to continuous learning package")
    optimization_reference: List[str] = Field(default_factory=list, description="Traceability reference list of optimization recommendation IDs")
    feedback_reference: Optional[str] = Field(None, description="Traceability reference path to feedback audit trail")
    referenced_threat_report_reference: str = Field(..., description="Traceability reference path to referenced threat report")
