from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional, Union
from datetime import datetime

class ResponsePackageInfo(BaseModel):
    response_package_id: str
    report_id: str
    incident_id: str
    package_timestamp: datetime
    package_version: str
    package_status: str

class ResponseDecisionTrace(BaseModel):
    decision_factors: List[str]
    selected_rule: str

class IncidentResponsePlan(BaseModel):
    incident_type: str
    response_strategy: str
    recommended_actions: List[str]
    business_justification: str
    expected_outcome: str
    response_decision_trace: Optional[ResponseDecisionTrace] = None

class ResponseExecutionPlan(BaseModel):
    action_sequence: List[str]
    execution_type: str
    assigned_team: str
    execution_priority: str
    estimated_completion_time: str

class SOARTask(BaseModel):
    task_id: str
    playbook_name: str
    automation_level: str
    prerequisites: List[str]
    execution_status: str

class AnalystValidation(BaseModel):
    analyst_decision: str
    validation_notes: str
    override_reason: Optional[str] = None
    approval_timestamp: datetime

class ContinuousLearningPackage(BaseModel):
    analyst_verdict: str
    learning_label: str
    contributing_patterns: List[str]
    contextual_features: Union[List[str], Dict[str, Any]]
    learning_priority: str

class ModelOptimizationRecommendation(BaseModel):
    suspected_affected_modules: List[str]
    optimization_target: str
    recommendation: str
    supporting_feedback: str
    retraining_candidate: bool

class FeedbackAuditTrail(BaseModel):
    feedback_id: str
    analyst_id: str
    decision_history: List[Dict[str, Any]]
    feedback_timestamp: datetime
    audit_status: str

class ReferencedExplainableThreatReport(BaseModel):
    report_id: str
    executive_summary_reference: Dict[str, Any]
    root_cause_reference: Dict[str, Any]
    evidence_reference: Dict[str, Any]
    investigation_reference: Dict[str, Any]
    analyst_support_reference: Dict[str, Any]

class IncidentResponseLearningPackage(BaseModel):
    response_package_info: ResponsePackageInfo
    incident_response_plan: IncidentResponsePlan
    response_execution_plan: ResponseExecutionPlan
    soar_orchestration_tasks: List[SOARTask] = Field(default_factory=list)
    analyst_validation: Optional[AnalystValidation] = None
    continuous_learning_package: Optional[ContinuousLearningPackage] = None
    model_optimization_recommendations: List[ModelOptimizationRecommendation] = Field(default_factory=list)
    feedback_audit_trail: Optional[FeedbackAuditTrail] = None
    referenced_threat_report: ReferencedExplainableThreatReport
