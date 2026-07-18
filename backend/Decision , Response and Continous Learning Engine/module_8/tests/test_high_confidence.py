import pytest
from module_8.main import process_threat_report, apply_analyst_decision

def test_high_confidence_critical_incident(base_etr_payload):
    # Process initial payload
    package = process_threat_report(base_etr_payload)
    
    # Assert response plan generated correctly from template
    assert package.incident_response_plan.incident_type == "Ransomware"
    assert package.incident_response_plan.response_strategy == "Containment"
    
    # Assert SOAR tasks created in Prepared state
    assert len(package.soar_orchestration_tasks) > 0
    assert package.soar_orchestration_tasks[0].execution_status == "Prepared"
    assert package.response_package_info.package_status == "PendingApproval"
    
    # Analyst approves it as True Positive
    updated_package = apply_analyst_decision(
        package=package,
        etr_payload=base_etr_payload,
        analyst_id="analyst_99",
        decision="Approved",
        verdict="True Positive",
        notes="Confirmed ransomware infection."
    )
    
    # Assert validation
    assert updated_package.analyst_validation.analyst_decision == "Approved"
    assert updated_package.response_package_info.package_status == "Approved"
    
    # Assert SOAR tasks advanced to Ready
    assert updated_package.soar_orchestration_tasks[0].execution_status == "Ready"
    
    # Assert learning package created
    assert updated_package.continuous_learning_package is not None
    assert updated_package.continuous_learning_package.learning_label == "positive"
