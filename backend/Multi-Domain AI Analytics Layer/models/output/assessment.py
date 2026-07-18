from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, ConfigDict

# =====================================================================
# ASSESSMENT INFORMATION
# =====================================================================
class AssessmentInformation(BaseModel):
    assessment_id: str = Field(..., description="Unique generated assessment ID (e.g. DAA-YYYYMMDD-XXXX)")
    incident_id: str = Field(..., description="Incident ID under analysis")
    incident_category: str = Field(..., description="Category determined for the incident")
    assessment_timestamp: datetime = Field(..., description="Timestamp of the assessment execution")
    active_domains: List[str] = Field(..., description="List of active analytics domains (e.g. Behaviour, Fraud)")

# =====================================================================
# BEHAVIOUR ASSESSMENT SUB-MODELS
# =====================================================================
class BehaviouralAnomaly(BaseModel):
    anomaly_id: str
    anomaly_type: str
    severity: str
    description: str
    supporting_events: List[str]
    supporting_graph_nodes: List[str]
    confidence: float

class BehaviourAssessment(BaseModel):
    behavioural_anomalies: List[BehaviouralAnomaly] = Field(default_factory=list)
    behavioural_patterns: List[str] = Field(default_factory=list)
    behavioural_risk_score: float
    confidence: float
    supporting_evidence: List[str] = Field(default_factory=list)

# =====================================================================
# FRAUD ASSESSMENT SUB-MODELS
# =====================================================================
class SuspiciousTransaction(BaseModel):
    transaction_id: str
    transaction_type: str
    amount: float
    currency: str
    risk_reason: str
    severity: str
    confidence: float
    timeline_reference: List[int]
    graph_reference: List[str]

class HighRiskBeneficiary(BaseModel):
    beneficiary_id: str
    beneficiary_type: str
    beneficiary_risk_reason: str
    linked_transactions: List[str]
    confidence: float

class MuleAccountDetection(BaseModel):
    detected: bool
    confidence: float
    supporting_evidence: List[str]
    linked_accounts: List[str]
    linked_transactions: List[str]

class FraudAssessment(BaseModel):
    fraud_patterns: List[str] = Field(default_factory=list)
    suspicious_transactions: List[SuspiciousTransaction] = Field(default_factory=list)
    high_risk_beneficiaries: List[HighRiskBeneficiary] = Field(default_factory=list)
    mule_account_detected: Optional[MuleAccountDetection] = None
    transaction_risk_score: float
    confidence: float
    supporting_evidence: List[str] = Field(default_factory=list)

# =====================================================================
# CYBER ASSESSMENT SUB-MODELS
# =====================================================================
class CompromisedAsset(BaseModel):
    asset_id: str
    asset_type: str
    asset_name: str
    compromise_reason: str
    severity: str
    confidence: float
    graph_reference: List[str]

class LateralMovement(BaseModel):
    detected: bool
    confidence: float
    movement_path: List[str]
    affected_assets: List[str]
    supporting_evidence: List[str]

class MalwarePresence(BaseModel):
    detected: bool
    malware_family: str
    malware_type: str
    ioc_matches: List[str]
    confidence: float
    supporting_evidence: List[str]

class CyberAssessment(BaseModel):
    detected_attack_pattern: str
    attack_stage: str
    compromised_assets: List[CompromisedAsset] = Field(default_factory=list)
    lateral_movement: Optional[LateralMovement] = None
    malware_presence: Optional[MalwarePresence] = None
    cyber_risk_score: float
    confidence: float
    supporting_evidence: List[str] = Field(default_factory=list)

# =====================================================================
# QUANTUM ASSESSMENT SUB-MODELS
# =====================================================================
class HNDLIndicator(BaseModel):
    indicator_id: str
    indicator_type: str
    description: str
    severity: str
    confidence: float
    supporting_references: List[str]

class EncryptedDataExposure(BaseModel):
    asset_id: str
    asset_type: str
    encrypted_data_type: str
    estimated_volume: str
    exposure_reason: str
    confidence: float
    graph_reference: List[str]

class LegacyCryptoAsset(BaseModel):
    asset_name: str
    algorithm: str
    algorithm_category: str
    risk_reason: str
    migration_priority: str
    confidence: float

class QuantumAssessment(BaseModel):
    HNDL_indicators: List[HNDLIndicator] = Field(default_factory=list)
    encrypted_data_exposure: List[EncryptedDataExposure] = Field(default_factory=list)
    legacy_crypto_assets: List[LegacyCryptoAsset] = Field(default_factory=list)
    quantum_risk_score: float
    confidence: float
    supporting_evidence: List[str] = Field(default_factory=list)

# =====================================================================
# ACTIVE DOMAIN ASSESSMENTS
# =====================================================================
class ActiveDomainAssessments(BaseModel):
    behaviour_assessment: Optional[BehaviourAssessment] = Field(None)
    fraud_assessment: Optional[FraudAssessment] = Field(None)
    cyber_assessment: Optional[CyberAssessment] = Field(None)
    quantum_assessment: Optional[QuantumAssessment] = Field(None)

    model_config = ConfigDict(populate_by_name=True)

# =====================================================================
# TRACEABILITY & INTEGRATION
# =====================================================================
class ReferencedCorrelatedSecurityIncident(BaseModel):
    incident_id: str = Field(..., description="ID of the source incident")
    timeline_reference: List[int] = Field(default_factory=list, description="Sequence numbers of timeline steps")
    attack_graph_reference: List[str] = Field(default_factory=list, description="Node or relationship IDs referenced")
    hypothesis_reference: List[str] = Field(default_factory=list, description="IDs of hypotheses matching this assessment")
    confidence_reference: float = Field(..., description="Overall confidence of the original incident")

    model_config = ConfigDict(populate_by_name=True)

class CompositeRiskAssessment(BaseModel):
    overall_risk_score: float
    overall_risk_level: str
    contributing_domains: List[str]
    assessment_confidence: float
    priority: str

class AIExplanation(BaseModel):
    explanation_summary: str
    contributing_engines: List[str]

# =====================================================================
# DOMAIN AI ASSESSMENT (ROOT MODEL)
# =====================================================================
class DomainAIAssessment(BaseModel):
    assessment_information: AssessmentInformation
    active_domain_assessments: Optional[ActiveDomainAssessments] = Field(None)
    cross_domain_intelligence: List[str] = Field(default_factory=list)
    composite_risk_assessment: CompositeRiskAssessment
    ai_explanation: AIExplanation
    recommended_actions: List[str] = Field(default_factory=list)
    referenced_correlated_security_incident: ReferencedCorrelatedSecurityIncident

    model_config = ConfigDict(populate_by_name=True)

