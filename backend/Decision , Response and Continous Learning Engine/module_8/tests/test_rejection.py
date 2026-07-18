import pytest
from module_8.main import process_threat_report, apply_analyst_decision

def test_rejection(base_etr_payload):
    package = process_threat_report(base_etr_payload)
    
    updated_package = apply_analyst_decision(
        package=package,
        etr_payload=base_etr_payload,
        analyst_id="analyst_99",
        decision="Rejected",
        verdict="Benign",
        notes="Incorrect correlation."
    )
    
    # Verify execution blocked
    assert updated_package.response_package_info.package_status == "Rejected"
    for task in updated_package.soar_orchestration_tasks:
        assert task.execution_status == "Blocked"
        
    # Verify audit updated
    assert updated_package.feedback_audit_trail is not None
    assert len(updated_package.feedback_audit_trail.decision_history) == 1
    assert updated_package.feedback_audit_trail.decision_history[0]["decision"] == "Rejected"
