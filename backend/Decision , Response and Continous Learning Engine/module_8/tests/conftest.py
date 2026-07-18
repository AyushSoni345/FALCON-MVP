import pytest
from typing import Dict, Any

@pytest.fixture
def base_etr_payload() -> Dict[str, Any]:
    return {
        "report_information": {
            "report_id": "rep_123",
            "risk_assessment_id": "risk_123",
            "incident_id": "inc_123",
            "report_timestamp": "2024-05-01T12:00:00Z",
            "report_version": "1.0",
            "report_status": "Final"
        },
        "executive_summary": {
            "incident_overview": "Ransomware detection",
            "unified_risk_score": 90.0,
            "risk_level": "Critical",
            "primary_cause": "Phishing",
            "business_impact": "High",
            "recommended_priority": "P1"
        },
        "incident_narrative": {
            "narrative_summary": "Attacker compromised credentials.",
            "attack_progression": ["Phishing", "Lateral Movement"],
            "affected_entities": ["user1"],
            "business_consequences": "Data loss"
        },
        "root_cause_analysis": {
            "probable_root_cause": "Compromised Credentials",
            "contributing_factors": ["No MFA"],
            "triggering_event": "Login from unknown IP",
            "impact_summary": "Data encrypted",
            "confidence": 0.95
        },
        "evidence_chain": {
            "evidence_sequence": ["ev1", "ev2"],
            "supporting_events": ["ev3"],
            "graph_paths": ["nodeA->nodeB"],
            "ai_assessments": ["assessment1"],
            "business_context": {"department": "Finance"}
        },
        "explainable_ai_reasoning": {
            "reasoning_steps": ["Step 1"],
            "supporting_factors": ["Factor A"],
            "contradictory_factors": [],
            "ai_decision_summary": "High risk pattern matched"
        },
        "human_readable_timeline": {
            "timeline_steps": [
                {
                    "timestamp": "2024-05-01T11:00:00Z",
                    "description": "Initial login",
                    "significance": "Started session"
                }
            ]
        },
        "investigation_guidance": {
            "recommended_investigation_steps": ["Check logs"],
            "priority_artifacts": ["Memory dump"],
            "additional_queries": ["Search other IPs"],
            "related_entities": ["Admin PC"],
            "recommended_validation": ["Validate user identity"]
        },
        "analyst_decision_support": {
            "confidence_summary": "High confidence",
            "escalation_recommendation": "Escalate to T3",
            "automation_recommendation": "Yes",
            "analyst_notes": ""
        },
        "referenced_unified_risk_assessment": {
            "risk_assessment_id": "risk_123",
            "incident_classification": "Ransomware",
            "context_aware_risk_score": 90.0,
            "confidence_assessment": "High",
            "prioritization_decision": "Immediate",
            "response_priority": "P1"
        }
    }
