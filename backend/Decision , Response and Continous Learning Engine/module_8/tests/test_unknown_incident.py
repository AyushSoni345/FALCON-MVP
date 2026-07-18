import pytest
from module_8.main import process_threat_report
import copy

def test_unknown_incident_type(base_etr_payload):
    payload = copy.deepcopy(base_etr_payload)
    # Give it an unknown classification
    payload["referenced_unified_risk_assessment"]["incident_classification"] = "Alien Invasion"
    payload["executive_summary"]["unified_risk_score"] = 10.0
    payload["executive_summary"]["risk_level"] = "Low"
    
    package = process_threat_report(payload)
    
    # Should fall back gracefully to the default strategy
    assert package.incident_response_plan.response_strategy == "Investigation & Monitoring"
    assert package.incident_response_plan.expected_outcome == "Event tracked for future reference."
