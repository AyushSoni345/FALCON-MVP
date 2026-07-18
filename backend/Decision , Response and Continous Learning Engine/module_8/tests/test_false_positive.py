import pytest
from module_8.main import process_threat_report, apply_analyst_decision

def test_false_positive(base_etr_payload):
    # Process initial payload
    package = process_threat_report(base_etr_payload)
    
    # Analyst modifies it as False Positive
    updated_package = apply_analyst_decision(
        package=package,
        etr_payload=base_etr_payload,
        analyst_id="analyst_99",
        decision="Modified",
        verdict="False Positive",
        notes="Analytics triggered on a normal backup process."
    )
    
    # Verify negative learning sample generated
    assert updated_package.continuous_learning_package.analyst_verdict == "False Positive"
    assert updated_package.continuous_learning_package.learning_label == "negative"
    
    # Verify optimization recommendation generated
    assert len(updated_package.model_optimization_recommendations) > 0
    optimization = updated_package.model_optimization_recommendations[0]
    assert "Module 5 Behaviour Analytics" in optimization.suspected_affected_modules
    
    # Verify status
    assert updated_package.response_package_info.package_status == "Modified"
