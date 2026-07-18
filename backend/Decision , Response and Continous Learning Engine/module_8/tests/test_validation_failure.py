import pytest
from module_8.main import process_threat_report
import copy

def test_validation_failure(base_etr_payload):
    payload = copy.deepcopy(base_etr_payload)
    # Remove a required field
    del payload["executive_summary"]["risk_level"]
    
    with pytest.raises(ValueError) as exc:
        process_threat_report(payload)
        
    assert "Invalid ExplainableThreatReport schema" in str(exc.value)
