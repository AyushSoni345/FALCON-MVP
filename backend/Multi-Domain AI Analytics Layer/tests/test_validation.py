import pytest
from module5.utils.validation import validate_incident
from module5.exceptions.exceptions import InvalidIncidentException
from module5.models.input.incident import CorrelatedSecurityIncident
from module5.tests.conftest import create_base_incident

def test_validation_success():
    incident = create_base_incident()
    # Should not raise exception
    validate_incident(incident)

def test_validation_missing_id():
    incident = create_base_incident()
    incident.incident_information.incident_id = ""
    with pytest.raises(InvalidIncidentException) as exc:
        validate_incident(incident)
    assert "Missing incident_id" in str(exc.value)

def test_validation_empty_timeline():
    incident = create_base_incident()
    incident.incident_timeline = []
    with pytest.raises(InvalidIncidentException) as exc:
        validate_incident(incident)
    assert "timeline must contain at least one step" in str(exc.value)

def test_validation_missing_confidence():
    incident = create_base_incident()
    incident.confidence_assessment = None
    with pytest.raises(InvalidIncidentException) as exc:
        validate_incident(incident)
    assert "Missing confidence_assessment" in str(exc.value)

def test_validation_backward_compatibility():
    raw_dict = {
        "incident_info": {
            "incident_id": "INC-COMPAT-01",
            "incident_type": "Account Takeover",
            "incident_category": "Financial",
            "incident_status": "Active",
            "incident_start_time": "2026-07-15T12:00:00",
            "incident_end_time": "2026-07-15T12:05:00",
            "incident_duration": 300.0,
            "primary_entity": "USR-111",
            "affected_assets": 1,
            "correlated_event_count": 1
        },
        "incident_timeline": [
            {
                "sequence_number": 1,
                "timestamp": "2026-07-15T12:00:00",
                "event_uuid": "evt-compat",
                "action": "LOGIN",
                "entity": "USR-111",
                "confidence": 0.9
            }
        ],
        "correlated_evidence": {
            "related_events": ["evt-compat"],
            "behavioral_anomalies": [],
            "malware_matches": [],
            "IOC_matches": []
        },
        "attack_graph": {
            "attack_nodes": [{"node_id": "USR-111", "node_type": "User"}],
            "attack_relationships": [],
            "attack_entry_point": "192.168.10.5",
            "attack_exit_point": "SRV-LEDGER",
            "lateral_movements": []
        },
        "ai_reasoning": {
            "reasoning_chain": ["Step 1 observed."],
            "supporting_patterns": [],
            "graph_observations": [],
            "temporal_observations": [],
            "anomaly_summary": "Normal.",
            "relationship_summary": "User connected to IP."
        },
        "threat_hypotheses": [],
        "confidence_assessment": {
            "overall_confidence": 0.8,
            "temporal_confidence": 0.8,
            "graph_confidence": 0.8,
            "behavioral_confidence": 0.8,
            "threat_intelligence_confidence": 0.8,
            "fraud_confidence": 0.8,
            "evidence_score": 0.8,
            "uncertainty_score": 0.2
        },
        "incident_context": {
            "affected_customers": ["CUST-111"],
            "affected_employees": [],
            "affected_accounts": [],
            "affected_transactions": [],
            "affected_devices": [],
            "affected_servers": [],
            "affected_applications": [],
            "business_process": "Transfers"
        },
        "investigation_context": {
            "first_observed_event": "2026-07-15T12:00:00",
            "latest_event": "2026-07-15T12:05:00",
            "historical_similarity": 0.5
        },
        "predictive_intelligence": {
            "predictions_enabled": False
        },
        "referenced_security_graph_events": []
    }
    
    incident = CorrelatedSecurityIncident.model_validate(raw_dict)
    assert incident.incident_information.incident_id == "INC-COMPAT-01"
