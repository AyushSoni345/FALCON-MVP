from datetime import datetime
from typing import List, Dict, Any, Optional, Union
from pydantic import BaseModel, Field, ConfigDict, model_validator
from app.models.enums import RiskLevel

class DomainAssessmentDetails(BaseModel):
    domain_score: float = Field(..., ge=0.0, le=100.0)
    confidence: float = Field(..., ge=0.0, le=1.0)
    findings: List[str] = Field(default_factory=list)

class ActiveDomainAssessments(BaseModel):
    behaviour_assessment: Optional[DomainAssessmentDetails] = None
    fraud_assessment: Optional[DomainAssessmentDetails] = None
    cyber_assessment: Optional[DomainAssessmentDetails] = None
    quantum_assessment: Optional[DomainAssessmentDetails] = None

class CrossDomainIntelligence(BaseModel):
    source_domain: str
    target_domain: str
    shared_indicator: str
    impact: str
    correlation_strength: float = Field(default=0.8, ge=0.0, le=1.0)

class CompositeRiskAssessment(BaseModel):
    overall_risk_score: float = Field(..., ge=0.0, le=100.0)
    overall_risk_level: str
    contributing_domains: List[str]
    assessment_confidence: float
    priority: str

class AssessmentInformation(BaseModel):
    risk_assessment_id: str = Field(..., description="Unique Risk Assessment ID", examples=["URA-20260715-0001"])
    incident_id: str = Field(..., description="Incident ID reference", examples=["INC-12345"])
    assessment_id: str = Field(..., description="Domain assessment ID reference", examples=["DAA-20260715-0001"])
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Timestamp of risk evaluation")
    assessment_timestamp: str = Field(default="", description="Timestamp string of risk evaluation")
    incident_category: str = Field(default="Cyber", description="Incident category from Module 6")
    schema_version: str = Field(default="1.0.0", description="Schema version of Module 6 output", examples=["1.0.0"])
    primary_entity: str = Field(default="Unknown Entity", description="Primary entity implicated in the incident", examples=["USR-MOCK"])
    incident_start_time: datetime = Field(default_factory=datetime.utcnow, description="Start timestamp of the incident")
    incident_end_time: datetime = Field(default_factory=datetime.utcnow, description="End timestamp of the incident")
    incident_duration: float = Field(default=0.0, description="Incident duration in seconds", examples=[10.0])
    affected_assets: int = Field(default=1, description="Count of distinct assets/entities impacted", examples=[1])

    @model_validator(mode="before")
    @classmethod
    def normalize_timestamps(cls, data: Any) -> Any:
        if isinstance(data, dict):
            ts_str = data.get("assessment_timestamp") or data.get("timestamp")
            if ts_str:
                if isinstance(ts_str, datetime):
                    dt = ts_str
                    ts_str = dt.isoformat() + "Z"
                else:
                    try:
                        dt = datetime.fromisoformat(str(ts_str).replace("Z", "+00:00"))
                    except Exception:
                        dt = datetime.utcnow()
                data["timestamp"] = dt
                data["assessment_timestamp"] = str(ts_str)
                if "incident_start_time" not in data or data["incident_start_time"] is None:
                    data["incident_start_time"] = dt
                if "incident_end_time" not in data or data["incident_end_time"] is None:
                    data["incident_end_time"] = dt
        return data

class BusinessContext(BaseModel):
    business_criticality: str = Field(..., description="Business criticality rating", examples=["High"])
    business_process: str = Field(..., description="Impacted business process", examples=["Retail Transfers"])
    service_impact: str = Field(..., description="Operational service impact description", examples=["High-risk transaction risk on consumer retail endpoint."])

class AssetContext(BaseModel):
    asset_criticality: str = Field(..., description="Criticality of the primary asset", examples=["High"])
    asset_type: str = Field(..., description="Type of asset involved", examples=["Database Ledger"])
    production_system: Union[bool, str] = Field(..., description="Target production system name", examples=["SRV-LEDGER"])

class CustomerContext(BaseModel):
    customer_segment: str = Field(..., description="Customer classification segment", examples=["High Net Worth"])
    customer_risk_profile: str = Field(..., description="Risk profile rating", examples=["Medium-High"])
    vulnerable_customer: bool = Field(..., description="Flag indicating if customer is vulnerable")
    high_net_worth_customer: bool = Field(..., description="Flag indicating if customer is HNWI")

class TransactionContext(BaseModel):
    transaction_value: float = Field(..., description="Fiat value of transaction", examples=[500000.0])
    transaction_frequency: str = Field(..., description="Frequency profile rating", examples=["High"])
    payment_channel: str = Field(..., description="Channel of transaction", examples=["IMPS"])
    financial_exposure: float = Field(..., description="Estimated overall financial exposure", examples=[500000.0])

class DataContext(BaseModel):
    data_classification: str = Field(..., description="Data classification level", examples=["Confidential"])
    pii_exposure: Union[bool, str] = Field(..., description="Severity of PII exposure risk", examples=["None"])
    credential_exposure: Union[bool, str] = Field(..., description="Type of credential exposure risk", examples=["Anomalous Session Credentials"])
    cryptographic_asset: Union[bool, str] = Field(..., description="Associated cryptographic asset name", examples=["Backup Archive Asymmetric Keys"])

class ContextEvaluation(BaseModel):
    business_context: BusinessContext = Field(..., description="Business context variables")
    asset_context: AssetContext = Field(..., description="Asset context variables")
    customer_context: CustomerContext = Field(..., description="Customer profile parameters")
    transaction_context: TransactionContext = Field(..., description="Financial transaction variables")
    data_context: DataContext = Field(..., description="Data sensitivity and cryptographic details")

class RiskSignalAggregation(BaseModel):
    contributing_domains: List[str] = Field(..., description="List of active assessment domains")
    domain_scores: Dict[str, float] = Field(..., description="Individual risk scores per domain")
    weighted_scores: Dict[str, float] = Field(..., description="Weighted contribution of each domain score")
    aggregated_score: float = Field(..., description="Aggregated base risk score before business rules adjustments")

class ContextAwareRiskScore(BaseModel):
    unified_risk_score: float = Field(..., description="Final context-aware risk score (0.0 to 100.0)")
    risk_level: str = Field(..., description="Risk level rating")
    risk_trend: str = Field(..., description="Trend rating")
    scoring_factors: Union[List[str], Dict[str, float]] = Field(..., description="Factors contributing to the final risk score")

class IncidentClassification(BaseModel):
    final_incident_type: str = Field(..., description="Classification category", examples=["Account Takeover"])
    final_priority: str = Field(..., description="Priority categorization", examples=["P1"])
    business_impact: str = Field(..., description="Impact description on business process", examples=["High-risk retail transfer threat on HNWI account."])
    operational_impact: str = Field(..., description="Impact description on system operations", examples=["High risk of ledger endpoint compromise."])
    financial_impact: str = Field(..., description="Financial impact or threat scale", examples=["₹5,00,000 exposure."])

class ConfidenceAssessment(BaseModel):
    overall_confidence: float = Field(..., description="Combined assessment confidence (0.0 to 1.0)", examples=[0.85])
    ai_confidence: float = Field(..., description="Confidence based on AI engines", examples=[0.9])
    business_context_confidence: float = Field(..., description="Confidence based on business metrics", examples=[0.8])
    evidence_strength: float = Field(..., description="Quality score of available evidence", examples=[0.85])
    false_positive_probability: float = Field(..., description="Calculated false positive probability", examples=[0.15])

class PrioritizationDecision(BaseModel):
    priority_level: str = Field(..., description="Final priority assignment level (e.g. P1)", examples=["P1"])
    escalation_required: bool = Field(..., description="Flag indicating if analyst escalation is required")
    false_positive_suppressed: bool = Field(..., description="Flag indicating if alert is suppressed as false positive")
    suppression_reason: Optional[str] = Field(None, description="Reason for suppression, if any")
    analyst_review_required: bool = Field(..., description="Flag indicating if analyst review is needed")

class ResponsePriority(BaseModel):
    recommended_response_level: str = Field(..., description="Urgency level response instruction", examples=["Immediate"])
    response_sla: str = Field(..., description="SLA for response", examples=["30m"])
    response_urgency: str = Field(..., description="Response urgency rating", examples=["High"])
    automation_eligible: bool = Field(..., description="Flag indicating automation eligibility")

class ReferencedDomainAIAssessment(BaseModel):
    assessment_id: str = Field(..., description="Referenced domain assessment ID")
    incident_id: str = Field(..., description="Referenced incident ID")
    active_domain_assessments: Union[List[str], ActiveDomainAssessments] = Field(..., description="Active assessment domains")
    cross_domain_intelligence: Union[List[str], CrossDomainIntelligence, None] = Field(default=None, description="Cross-domain intelligence link")
    composite_risk_assessment: Union[Dict[str, Any], CompositeRiskAssessment] = Field(..., description="Composite risk parameters")

class UnifiedRiskAssessment(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        frozen=True,
        json_schema_extra={
            "example": {
                "assessment_information": {
                    "risk_assessment_id": "URA-20260715-0001",
                    "incident_id": "INC-12345",
                    "assessment_id": "DAA-20260715-0001",
                    "timestamp": "2026-07-15T14:00:00Z",
                    "schema_version": "1.0.0",
                    "primary_entity": "USR-MOCK",
                    "incident_start_time": "2026-07-15T13:50:00Z",
                    "incident_end_time": "2026-07-15T14:00:00Z",
                    "incident_duration": 600.0,
                    "affected_assets": 1
                },
                "context_evaluation": {
                    "business_context": {
                        "business_criticality": "High",
                        "business_process": "Retail Transfers",
                        "service_impact": "High-risk transaction risk on consumer retail endpoint."
                    },
                    "asset_context": {
                        "asset_criticality": "High",
                        "asset_type": "Database Ledger",
                        "production_system": "SRV-LEDGER"
                    },
                    "customer_context": {
                        "customer_segment": "High Net Worth",
                        "customer_risk_profile": "Medium-High",
                        "vulnerable_customer": False,
                        "high_net_worth_customer": True
                    },
                    "transaction_context": {
                        "transaction_value": 500000.0,
                        "transaction_frequency": "High",
                        "payment_channel": "IMPS",
                        "financial_exposure": 500000.0
                    },
                    "data_context": {
                        "data_classification": "Confidential",
                        "pii_exposure": "None",
                        "credential_exposure": "Anomalous Session Credentials",
                        "cryptographic_asset": "Backup Archive Asymmetric Keys"
                    }
                },
                "risk_signal_aggregation": {
                    "contributing_domains": ["Behaviour", "Fraud"],
                    "domain_scores": {
                        "Behaviour": 75.0,
                        "Fraud": 85.0
                    },
                    "weighted_scores": {
                        "Behaviour": 37.5,
                        "Fraud": 42.5
                    },
                    "aggregated_score": 80.0
                },
                "context_aware_risk_score": {
                    "unified_risk_score": 85.5,
                    "risk_level": "High",
                    "risk_trend": "Stable",
                    "scoring_factors": ["ImpossibleTravel", "HNWIPresent"]
                },
                "incident_classification": {
                    "final_incident_type": "Account Takeover",
                    "final_priority": "P1",
                    "business_impact": "High-risk retail transfer threat on HNWI account.",
                    "operational_impact": "High risk of ledger endpoint compromise.",
                    "financial_impact": "₹5,000 exposure."
                },
                "confidence_assessment": {
                    "overall_confidence": 0.85,
                    "ai_confidence": 0.90,
                    "business_context_confidence": 0.80,
                    "evidence_strength": 0.85,
                    "false_positive_probability": 0.15
                },
                "prioritization_decision": {
                    "priority_level": "P1",
                    "escalation_required": True,
                    "false_positive_suppressed": False,
                    "suppression_reason": None,
                    "analyst_review_required": True
                },
                "response_priority": {
                    "recommended_response_level": "Immediate",
                    "response_sla": "30m",
                    "response_urgency": "High",
                    "automation_eligible": True
                },
                "referenced_domain_ai_assessment": {
                    "assessment_id": "DAA-20260715-0001",
                    "incident_id": "INC-12345",
                    "active_domain_assessments": ["Behaviour", "Fraud"],
                    "cross_domain_intelligence": None,
                    "composite_risk_assessment": {
                        "overall_risk_score": 85.0,
                        "priority": "P1"
                    }
                }
            }
        }
    )

    assessment_information: AssessmentInformation = Field(..., alias="Assessment Information")
    context_evaluation: ContextEvaluation = Field(..., alias="Context Evaluation")
    risk_signal_aggregation: RiskSignalAggregation = Field(..., alias="Risk Signal Aggregation")
    context_aware_risk_score: ContextAwareRiskScore = Field(..., alias="Context-Aware Risk Score")
    incident_classification: IncidentClassification = Field(..., alias="Incident Classification")
    confidence_assessment: ConfidenceAssessment = Field(..., alias="Confidence Assessment")
    prioritization_decision: PrioritizationDecision = Field(..., alias="Prioritization Decision")
    response_priority: ResponsePriority = Field(..., alias="Response Priority")
    referenced_domain_ai_assessment: ReferencedDomainAIAssessment = Field(..., alias="Referenced Domain AI Assessment")
