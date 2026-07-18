from datetime import datetime
from typing import List
from pydantic import BaseModel, Field, ConfigDict
from app.models.enums import ReportStatus, RiskLevel
from app.models.requests import (
    IncidentClassification,
    ContextAwareRiskScore,
    ConfidenceAssessment,
    PrioritizationDecision,
    ResponsePriority
)

class ReportInformation(BaseModel):
    report_id: str = Field(..., description="Unique Explainable Threat Report identifier (UUID)", examples=["550e8400-e29b-41d4-a716-446655440000"])
    risk_assessment_id: str = Field(..., description="Reference to Module 6 Risk Assessment ID", examples=["URA-20260715-0001"])
    incident_id: str = Field(..., description="Reference to Module 4 Incident ID", examples=["INC-12345"])
    report_timestamp: datetime = Field(..., description="Timestamp when report was generated", examples=["2026-07-15T15:00:00Z"])
    report_version: str = Field(..., description="Report schema version", examples=["1.0.0"])
    report_status: ReportStatus = Field(..., description="Status of the report (Draft or Final)", examples=[ReportStatus.FINAL])

class ExecutiveSummary(BaseModel):
    incident_overview: str = Field(..., description="Concise executive overview of the incident", examples=["The incident represents a high-severity Account Takeover attempt."])
    unified_risk_score: float = Field(..., description="Unified risk score received from Module 6", examples=[85.5])
    risk_level: RiskLevel = Field(..., description="Adjusted risk level", examples=[RiskLevel.HIGH])
    primary_cause: str = Field(..., description="The main trigger/cause of this risk score", examples=["Credential Theft"])
    business_impact: str = Field(..., description="Summary of the potential business impact", examples=["High-risk retail transfer threat on HNWI account."])
    recommended_priority: str = Field(..., description="Recommended investigation and response priority", examples=["P1"])

class IncidentNarrative(BaseModel):
    narrative_summary: str = Field(..., description="Brief summary of the attack narrative", examples=["An attacker logged in via an anomalous VPN session, registered a new beneficiary, and scheduled a transfer."])
    attack_progression: List[str] = Field(..., description="Detailed timeline progression in natural language paragraphs")
    affected_entities: List[str] = Field(..., description="List of users, accounts, and endpoints impacted")
    business_consequences: List[str] = Field(..., description="Consequences on business operations")

class RootCauseAnalysis(BaseModel):
    probable_root_cause: str = Field(..., description="Most probable origin of the incident", examples=["Compromised credentials via anomalous geo-location login."])
    contributing_factors: List[str] = Field(..., description="Factors that facilitated or escalated the incident")
    triggering_event: str = Field(..., description="Immediate event triggering the alert", examples=["Failed authentication attempt followed by login from new IP."])
    impact_summary: str = Field(..., description="Summary description of impacts", examples=["Exposure of financial transaction endpoint."])
    confidence: float = Field(..., description="Confidence score associated with this root cause", examples=[0.85])

class EvidenceChain(BaseModel):
    evidence_sequence: List[str] = Field(..., description="Step-by-step summary of structured evidence")
    supporting_events: List[str] = Field(..., description="Referenced Event UUIDs or log entries")
    graph_paths: List[str] = Field(..., description="Referenced Graph Node/Relationship Paths")
    ai_assessments: List[str] = Field(..., description="AI assessments and model decisions linked as evidence")
    business_context: List[str] = Field(..., description="Relevant business metrics and variables")

class ExplainableAIReasoning(BaseModel):
    reasoning_steps: List[str] = Field(..., description="Inferred reasoning sequence of the AI models")
    supporting_factors: List[str] = Field(..., description="Specific indicators that increased AI risk confidence")
    contradictory_factors: List[str] = Field(..., description="Indicators that weakened threat classification")
    ai_decision_summary: str = Field(..., description="Overall summary of the AI reasoning outcome", examples=["Multi-domain analysis confirms high-probability credential takeover."])

class HumanReadableTimelineEntry(BaseModel):
    timestamp: datetime = Field(..., description="Exact event timestamp")
    description: str = Field(..., description="Human-readable description of what occurred")
    significance: str = Field(..., description="Technical or operational significance of this event step")

class HumanReadableTimeline(BaseModel):
    entries: List[HumanReadableTimelineEntry] = Field(..., description="Chronological timeline entries")

class InvestigationGuidance(BaseModel):
    recommended_investigation_steps: List[str] = Field(..., description="Step-by-step guidance for investigating this incident class")
    priority_artifacts: List[str] = Field(..., description="Priority data structures and logs to inspect")
    additional_queries: List[str] = Field(..., description="Graph database or log repository queries to execute")
    related_entities: List[str] = Field(..., description="Identified entities related to the threat actors")
    recommended_validation: List[str] = Field(..., description="Steps to validate user identity or status")

class AnalystDecisionSupport(BaseModel):
    confidence_summary: str = Field(..., description="Summary of evidence confidence", examples=["High confidence due to multiple matching telemetry logs and IOC feeds."])
    escalation_recommendation: str = Field(..., description="Suggested escalation pathway", examples=["Escalate to Level 2 Fraud Operations."])
    automation_recommendation: str = Field(..., description="Action recommendation on automation viability", examples=["Eligible for automated SOAR workflow response."])
    analyst_notes: str = Field(..., description="Additional notes or observations for the analyst", examples=["Observed impossible travel coupled with high-value transaction request."])

class ReferencedUnifiedRiskAssessment(BaseModel):
    risk_assessment_id: str = Field(..., description="Unique Risk Assessment ID", examples=["URA-20260715-0001"])
    incident_classification: IncidentClassification = Field(..., description="Classification category object")
    context_aware_risk_score: ContextAwareRiskScore = Field(..., description="Risk score assigned by Module 6")
    confidence_assessment: ConfidenceAssessment = Field(..., description="Confidence assessment score details")
    prioritization_decision: PrioritizationDecision = Field(..., description="Prioritization class decision details")
    response_priority: ResponsePriority = Field(..., description="Response priority decision details")

class ExplainableThreatReport(BaseModel):
    model_config = ConfigDict(
        frozen=True
    )

    report_information: ReportInformation = Field(..., description="Report metadata")
    executive_summary: ExecutiveSummary = Field(..., description="Concise executive level overview")
    incident_narrative: IncidentNarrative = Field(..., description="Detailed timeline progression in natural language")
    root_cause_analysis: RootCauseAnalysis = Field(..., description="RCA detail and evidence analysis")
    evidence_chain: EvidenceChain = Field(..., description="Traceability matrix of raw data and signals")
    explainable_ai_reasoning: ExplainableAIReasoning = Field(..., description="Detailed explanation of AI inference steps")
    human_readable_timeline: HumanReadableTimeline = Field(..., description="Chronological sequence of actions")
    investigation_guidance: InvestigationGuidance = Field(..., description="Recommended analyst SOPs and queries")
    analyst_decision_support: AnalystDecisionSupport = Field(..., description="Decisions support metrics and notes")
    referenced_unified_risk_assessment: ReferencedUnifiedRiskAssessment = Field(..., description="Audit references to the source risk assessment")
