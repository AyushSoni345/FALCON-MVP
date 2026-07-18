from typing import Dict, List, Optional
from pydantic import BaseModel, Field, ConfigDict
from .domain_ai_assessment import DomainAssessmentDetails, CrossDomainIntelligence, CompositeRiskAssessment, ActiveDomainAssessments

class AssessmentInformation(BaseModel):
    risk_assessment_id: str
    incident_id: str
    assessment_id: str
    assessment_timestamp: str
    incident_category: str

class BusinessContext(BaseModel):
    business_criticality: str
    business_process: str
    service_impact: str

class AssetContext(BaseModel):
    asset_criticality: str
    asset_type: str
    production_system: bool

class CustomerContext(BaseModel):
    customer_segment: str
    customer_risk_profile: str
    vulnerable_customer: bool
    high_net_worth_customer: bool

class TransactionContext(BaseModel):
    transaction_value: float
    transaction_frequency: str
    payment_channel: str
    financial_exposure: float

class DataContext(BaseModel):
    data_classification: str
    pii_exposure: bool
    credential_exposure: bool
    cryptographic_asset: bool

class ContextEvaluation(BaseModel):
    business_context: BusinessContext
    asset_context: AssetContext
    customer_context: CustomerContext
    transaction_context: TransactionContext
    data_context: DataContext

class RiskSignalAggregation(BaseModel):
    contributing_domains: List[str]
    domain_scores: Dict[str, float]
    weighted_scores: Dict[str, float]
    aggregated_score: float

class ContextAwareRiskScore(BaseModel):
    unified_risk_score: float
    risk_level: str
    risk_trend: str
    scoring_factors: List[str]

class IncidentClassification(BaseModel):
    final_incident_type: str
    final_priority: str
    business_impact: str
    operational_impact: str
    financial_impact: str

class ConfidenceAssessment(BaseModel):
    overall_confidence: float
    ai_confidence: float
    business_context_confidence: float
    evidence_strength: float
    false_positive_probability: float

class PrioritizationDecision(BaseModel):
    priority_level: str
    escalation_required: bool
    false_positive_suppressed: bool
    suppression_reason: Optional[str] = None
    analyst_review_required: bool

class ResponsePriority(BaseModel):
    recommended_response_level: str
    response_sla: str
    response_urgency: str
    automation_eligible: bool

class ReferencedDomainAIAssessment(BaseModel):
    assessment_id: str
    incident_id: str
    active_domain_assessments: ActiveDomainAssessments
    cross_domain_intelligence: CrossDomainIntelligence
    composite_risk_assessment: CompositeRiskAssessment

class UnifiedRiskAssessment(BaseModel):
    assessment_information: AssessmentInformation = Field(..., alias="Assessment Information")
    context_evaluation: ContextEvaluation = Field(..., alias="Context Evaluation")
    risk_signal_aggregation: RiskSignalAggregation = Field(..., alias="Risk Signal Aggregation")
    context_aware_risk_score: ContextAwareRiskScore = Field(..., alias="Context-Aware Risk Score")
    incident_classification: IncidentClassification = Field(..., alias="Incident Classification")
    confidence_assessment: ConfidenceAssessment = Field(..., alias="Confidence Assessment")
    prioritization_decision: PrioritizationDecision = Field(..., alias="Prioritization Decision")
    response_priority: ResponsePriority = Field(..., alias="Response Priority")
    referenced_domain_ai_assessment: ReferencedDomainAIAssessment = Field(..., alias="Referenced Domain AI Assessment")

    model_config = ConfigDict(populate_by_name=True)
