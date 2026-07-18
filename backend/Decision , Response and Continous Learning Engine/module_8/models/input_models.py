from pydantic import BaseModel, model_validator
from typing import List, Dict, Any, Optional, Union
from datetime import datetime

class ReportInformation(BaseModel):
    report_id: str
    risk_assessment_id: str
    incident_id: str
    report_timestamp: str
    report_version: str
    report_status: str

class ExecutiveSummary(BaseModel):
    incident_overview: str
    unified_risk_score: Optional[float] = None
    risk_level: str
    primary_cause: str
    business_impact: str
    recommended_priority: str

class IncidentNarrative(BaseModel):
    narrative_summary: str
    attack_progression: List[str]
    affected_entities: List[str]
    business_consequences: Union[List[str], str]

class RootCauseAnalysis(BaseModel):
    probable_root_cause: str
    contributing_factors: List[str]
    triggering_event: str
    impact_summary: str
    confidence: Optional[float] = None

class EvidenceChain(BaseModel):
    evidence_sequence: List[Any]
    supporting_events: List[Any]
    graph_paths: List[Any]
    ai_assessments: List[Any]
    business_context: Union[List[str], Dict[str, Any]]

class ExplainableAIReasoning(BaseModel):
    reasoning_steps: List[str]
    supporting_factors: List[str]
    contradictory_factors: List[str]
    ai_decision_summary: str

class TimelineStep(BaseModel):
    timestamp: str
    description: str
    significance: str

class HumanReadableTimeline(BaseModel):
    timeline_steps: List[TimelineStep]

    @model_validator(mode="before")
    @classmethod
    def map_entries_to_steps(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "entries" in data and "timeline_steps" not in data:
                steps = []
                for entry in data["entries"]:
                    if isinstance(entry, dict):
                        steps.append({
                            "timestamp": str(entry.get("timestamp")),
                            "description": entry.get("description"),
                            "significance": entry.get("significance")
                        })
                    else:
                        steps.append({
                            "timestamp": str(getattr(entry, "timestamp", "")),
                            "description": getattr(entry, "description", ""),
                            "significance": getattr(entry, "significance", "")
                        })
                data["timeline_steps"] = steps
        return data

class InvestigationGuidance(BaseModel):
    recommended_investigation_steps: List[str]
    priority_artifacts: List[str]
    additional_queries: List[str]
    related_entities: List[str]
    recommended_validation: List[str]

class AnalystDecisionSupport(BaseModel):
    confidence_summary: str
    escalation_recommendation: str
    automation_recommendation: str
    analyst_notes: str

class ReferencedUnifiedRiskAssessment(BaseModel):
    risk_assessment_id: str
    incident_classification: str
    context_aware_risk_score: Optional[float] = None
    confidence_assessment: str
    prioritization_decision: str
    response_priority: str

    @model_validator(mode="before")
    @classmethod
    def normalize_nested_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            # incident_classification mapping
            ic = data.get("incident_classification")
            if isinstance(ic, dict):
                data["incident_classification"] = ic.get("final_incident_type")
            elif ic and not isinstance(ic, str):
                data["incident_classification"] = getattr(ic, "final_incident_type", str(ic))
                
            # context_aware_risk_score mapping
            cars = data.get("context_aware_risk_score")
            if isinstance(cars, dict):
                data["context_aware_risk_score"] = cars.get("unified_risk_score")
            elif cars and not isinstance(cars, (int, float)):
                data["context_aware_risk_score"] = getattr(cars, "unified_risk_score", None)
                
            # confidence_assessment mapping
            ca = data.get("confidence_assessment")
            if isinstance(ca, dict):
                data["confidence_assessment"] = str(ca.get("overall_confidence", "High"))
            elif ca and not isinstance(ca, str):
                data["confidence_assessment"] = str(getattr(ca, "overall_confidence", "High"))
                
            # prioritization_decision mapping
            pd = data.get("prioritization_decision")
            if isinstance(pd, dict):
                data["prioritization_decision"] = pd.get("priority_level", "P1")
            elif pd and not isinstance(pd, str):
                data["prioritization_decision"] = getattr(pd, "priority_level", "P1")
                
            # response_priority mapping
            rp = data.get("response_priority")
            if isinstance(rp, dict):
                data["response_priority"] = rp.get("recommended_response_level", "Immediate")
            elif rp and not isinstance(rp, str):
                data["response_priority"] = getattr(rp, "recommended_response_level", "Immediate")
                
        return data

class ExplainableThreatReport(BaseModel):
    report_information: ReportInformation
    executive_summary: ExecutiveSummary
    incident_narrative: IncidentNarrative
    root_cause_analysis: RootCauseAnalysis
    evidence_chain: EvidenceChain
    explainable_ai_reasoning: ExplainableAIReasoning
    human_readable_timeline: HumanReadableTimeline
    investigation_guidance: InvestigationGuidance
    analyst_decision_support: AnalystDecisionSupport
    referenced_unified_risk_assessment: ReferencedUnifiedRiskAssessment
