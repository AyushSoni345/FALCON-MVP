from datetime import datetime
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field, ConfigDict
from app.models.enums import ExecutionStatus, ValidationStatus, TeamRole

class ResponsePackageInfo(BaseModel):
    response_package_id: str = Field(..., description="Unique Response Package identifier (UUID)")
    report_id: str = Field(..., description="Referenced report identifier (UUID)")
    incident_id: str = Field(..., description="Referenced incident identifier")
    package_timestamp: datetime = Field(..., description="Timestamp of package creation")
    package_version: str = Field(..., description="Package schema version")
    package_status: str = Field(..., description="Status of the package")

class ResponseDecisionTrace(BaseModel):
    decision_factors: List[str] = Field(..., description="Factors contributing to response decision")
    selected_rule: str = Field(..., description="The matching containment rule name")

class IncidentResponsePlan(BaseModel):
    incident_type: str = Field(..., description="Threat classification type")
    response_strategy: str = Field(..., description="SOP strategy outline")
    recommended_actions: List[str] = Field(..., description="Action items array")
    business_justification: str = Field(..., description="Business criticality rationale")
    expected_outcome: str = Field(..., description="Target outcome description")
    response_decision_trace: ResponseDecisionTrace = Field(..., description="Trace of decision criteria")

class ResponseExecutionPlan(BaseModel):
    action_sequence: List[str] = Field(..., description="Order of response action execution")
    execution_type: str = Field(..., description="Type of execution flow (e.g. Automated, Semi-Automated)")
    assigned_team: str = Field(..., description="Assigned team role")
    execution_priority: str = Field(..., description="Priority assignment")
    estimated_completion_time: str = Field(..., description="Estimated completion duration/time")

class SOAROrchestrationTask(BaseModel):
    task_id: str = Field(..., description="Task ID in SOAR system (UUID)")
    playbook_name: str = Field(..., description="SOAR playbook name")
    automation_level: str = Field(..., description="Playbook automation level")
    prerequisites: List[str] = Field(..., description="Prerequisite tasks array")
    execution_status: str = Field(..., description="Status of SOAR tasks")

class AnalystValidation(BaseModel):
    analyst_decision: str = Field(..., description="Analyst verification label")
    validation_notes: str = Field(..., description="Validation notes logged by investigator")
    override_reason: Optional[str] = Field(None, description="Reason for override, if any")
    approval_timestamp: datetime = Field(..., description="Analyst approval timestamp")

class ContinuousLearningPackage(BaseModel):
    analyst_verdict: str = Field(..., description="Feedback verification verdict")
    learning_label: str = Field(..., description="Model classification training label")
    contributing_patterns: List[str] = Field(..., description="Identified threat patterns")
    contextual_features: Dict[str, Any] = Field(..., description="Contextual features metadata")
    learning_priority: str = Field(..., description="Priority level for retrain queue")

class ModelOptimizationRecommendation(BaseModel):
    affected_module: str = Field(..., description="Affected pipeline module name")
    optimization_target: str = Field(..., description="Optimization metric target")
    recommendation: str = Field(..., description="Weights recommendation description")
    supporting_feedback: str = Field(..., description="Feedback context")
    retraining_candidate: str = Field(..., description="Candidate event ID for retraining")

class FeedbackAuditTrail(BaseModel):
    feedback_id: str = Field(..., description="Audit entry ID (UUID)")
    analyst_id: str = Field(..., description="Analyst user ID")
    decision_history: List[str] = Field(..., description="Historical timeline log of analyst labels")
    feedback_timestamp: datetime = Field(..., description="Event timestamp")
    audit_status: str = Field(..., description="Audit loop review status")

class ExecutiveSummaryReference(BaseModel):
    unified_risk_score: float = Field(..., description="Unified risk score")
    risk_level: str = Field(..., description="Severity level of the threat")

class RootCauseReference(BaseModel):
    probable_root_cause: str = Field(..., description=" Rationale explaining probable root cause")

class EvidenceReference(BaseModel):
    evidence_count: int = Field(..., description="Number of supporting logs / events")

class InvestigationReference(BaseModel):
    priority_artifacts: List[str] = Field(..., description="List of high priority investigation logs/systems")

class AnalystSupportReference(BaseModel):
    confidence_summary: str = Field(..., description="Calculated metric confidence summary")

class ReferencedThreatReport(BaseModel):
    report_id: str = Field(..., description="Referenced report identifier (UUID)")
    executive_summary_reference: ExecutiveSummaryReference = Field(..., description="Executive report details")
    root_cause_reference: RootCauseReference = Field(..., description="RCA metrics")
    evidence_reference: EvidenceReference = Field(..., description="Evidence logs count")
    investigation_reference: InvestigationReference = Field(..., description="SOP guidance and priority artifacts")
    analyst_support_reference: AnalystSupportReference = Field(..., description="Analyst decision support parameters")

class IncidentResponseLearningPackage(BaseModel):
    model_config = ConfigDict(frozen=True)

    response_package_info: ResponsePackageInfo = Field(..., description="Response Package administrative metadata")
    incident_response_plan: IncidentResponsePlan = Field(..., description="Incident Response Plan details")
    response_execution_plan: ResponseExecutionPlan = Field(..., description="Response execution and assigned team")
    soar_orchestration_tasks: List[SOAROrchestrationTask] = Field(..., description="SOAR tasks lists")
    analyst_validation: Optional[AnalystValidation] = Field(None, description="Analyst decision and approval audit log")
    continuous_learning_package: Optional[ContinuousLearningPackage] = Field(None, description="Learning labels and features")
    model_optimization_recommendations: List[ModelOptimizationRecommendation] = Field(default_factory=list, description="Model optimization and retraining targets")
    feedback_audit_trail: Optional[List[FeedbackAuditTrail]] = Field(None, description="Feedback audit timeline logs")
    referenced_threat_report: ReferencedThreatReport = Field(..., description="Reference report from Module 8")
