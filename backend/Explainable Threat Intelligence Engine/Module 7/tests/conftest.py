import pytest
from datetime import datetime
from app.models.enums import RiskLevel
from app.models.requests import (
    UnifiedRiskAssessment,
    AssessmentInformation,
    ContextEvaluation,
    BusinessContext,
    AssetContext,
    CustomerContext,
    TransactionContext,
    DataContext,
    RiskSignalAggregation,
    ContextAwareRiskScore,
    IncidentClassification,
    ConfidenceAssessment,
    PrioritizationDecision,
    ResponsePriority,
    ReferencedDomainAIAssessment
)

def create_base_assessment_input(
    risk_assessment_id: str = "URA-20260715-0001",
    incident_id: str = "INC-12345",
    assessment_id: str = "DAA-20260715-0001",
    incident_classification: str = "Account Takeover",
    risk_level: RiskLevel = RiskLevel.HIGH,
    risk_score: float = 85.5,
    has_fraud: bool = False
) -> UnifiedRiskAssessment:
    
    timestamp = datetime.fromisoformat("2026-07-15T14:00:00+00:00")

    info = AssessmentInformation(
        risk_assessment_id=risk_assessment_id,
        incident_id=incident_id,
        assessment_id=assessment_id,
        timestamp=timestamp,
        schema_version="1.0.0",
        primary_entity="USR-MOCK",
        incident_start_time=timestamp,
        incident_end_time=timestamp,
        incident_duration=10.0,
        affected_assets=1
    )

    business_ctx = BusinessContext(
        business_criticality="High",
        business_process="Retail Transfers",
        service_impact="High-risk transaction risk on consumer retail endpoint."
    )

    asset_ctx = AssetContext(
        asset_criticality="High",
        asset_type="Database Ledger",
        production_system="SRV-LEDGER"
    )

    customer_ctx = CustomerContext(
        customer_segment="High Net Worth",
        customer_risk_profile="Medium-High",
        vulnerable_customer=False,
        high_net_worth_customer=True
    )

    transaction_ctx = TransactionContext(
        transaction_value=500000.0,
        transaction_frequency="High",
        payment_channel="IMPS",
        financial_exposure=500000.0
    )

    data_ctx = DataContext(
        data_classification="Confidential",
        pii_exposure="None",
        credential_exposure="Anomalous Session Credentials",
        cryptographic_asset="Backup Archive Asymmetric Keys"
    )

    eval_sec = ContextEvaluation(
        business_context=business_ctx,
        asset_context=asset_ctx,
        customer_context=customer_ctx,
        transaction_context=transaction_ctx,
        data_context=data_ctx
    )

    active_domains = ["Behaviour"]
    cross_domain_intel = []
    ai_summary = "Behaviour anomalies matched with suspicious transaction criteria."
    if has_fraud:
        active_domains.append("Fraud")
        cross_domain_intel.append("Behaviour anomalies matched with suspicious transaction criteria.")

    sig = RiskSignalAggregation(
        contributing_domains=active_domains,
        domain_scores={"Behaviour": 75.0, "Fraud": 85.0} if has_fraud else {"Behaviour": 75.0},
        weighted_scores={"Behaviour": 37.5, "Fraud": 42.5} if has_fraud else {"Behaviour": 37.5},
        aggregated_score=80.0 if has_fraud else 75.0
    )

    score_sec = ContextAwareRiskScore(
        unified_risk_score=risk_score,
        risk_level=risk_level,
        risk_trend="Stable",
        scoring_factors={"ImpossibleTravel": 40.0, "HNWIPresent": 20.0}
    )

    classification = f"Account Takeover"

    conf_sec = ConfidenceAssessment(
        overall_confidence=0.85,
        ai_confidence=0.9,
        business_context_confidence=0.8,
        evidence_strength=0.85,
        false_positive_probability=0.15
    )

    prioritization = PrioritizationDecision(
        priority_level="P1",
        escalation_required=True,
        false_positive_suppressed=False,
        suppression_reason=None,
        analyst_review_required=True
    )

    response_sec = ResponsePriority(
        recommended_response_level="Immediate",
        response_sla="30m",
        response_urgency="High",
        automation_eligible=True
    )

    ref_m5 = ReferencedDomainAIAssessment(
        assessment_id=assessment_id,
        incident_id=incident_id,
        active_domain_assessments=active_domains,
        cross_domain_intelligence=cross_domain_intel,
        composite_risk_assessment={"overall_risk_score": 85.0, "priority": "P1"}
    )

    return UnifiedRiskAssessment(
        assessment_information=info,
        context_evaluation=eval_sec,
        risk_signal_aggregation=sig,
        context_aware_risk_score=score_sec,
        incident_classification=IncidentClassification(
            final_incident_type=incident_classification,
            final_priority="P1",
            business_impact="High-risk retail transfer threat on HNWI account.",
            operational_impact="High risk of ledger endpoint compromise.",
            financial_impact="₹5,00,000 exposure."
        ),
        confidence_assessment=conf_sec,
        prioritization_decision=prioritization,
        response_priority=response_sec,
        referenced_domain_ai_assessment=ref_m5
    )

@pytest.fixture
def mock_assessment():
    return create_base_assessment_input()

@pytest.fixture
def mock_assessment_with_fraud():
    return create_base_assessment_input(has_fraud=True)
