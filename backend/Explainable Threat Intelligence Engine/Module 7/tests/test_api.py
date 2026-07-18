import pytest
from fastapi.testclient import TestClient
from app.main import app
from tests.conftest import create_base_assessment_input

client = TestClient(app)

def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"
    assert response.json()["module"] == "Module 7 - Explainable Threat Intelligence Engine"

def test_explain_endpoint_success():
    assessment = create_base_assessment_input()
    payload = assessment.model_dump(mode="json")
    
    response = client.post("/api/v1/explain", json=payload)
    assert response.status_code == 200
    
    json_data = response.json()
    assert "report_information" in json_data
    assert "executive_summary" in json_data
    assert "incident_narrative" in json_data
    assert "root_cause_analysis" in json_data
    assert "evidence_chain" in json_data
    assert "explainable_ai_reasoning" in json_data
    assert "human_readable_timeline" in json_data
    assert "investigation_guidance" in json_data
    assert "analyst_decision_support" in json_data
    assert "referenced_unified_risk_assessment" in json_data
    
    # Check trace refs are correct
    assert json_data["report_information"]["risk_assessment_id"] == "URA-20260715-0001"
    assert json_data["report_information"]["incident_id"] == "INC-12345"

def test_explain_endpoint_validation_error_mismatched_refs():
    assessment = create_base_assessment_input()
    # Modify inner domain AI assessment_id to mismatch
    assessment.referenced_domain_ai_assessment.assessment_id = "DAA-MISMATCH"
    payload = assessment.model_dump(mode="json")
    
    response = client.post("/api/v1/explain", json=payload)
    assert response.status_code == 400
    assert response.json()["error"] == "ValidationError"
    assert "Mismatched assessment_id reference" in response.json()["detail"]

def test_explain_endpoint_validation_error_empty_id():
    assessment = create_base_assessment_input()
    assessment.assessment_information.risk_assessment_id = " "
    payload = assessment.model_dump(mode="json")
    
    response = client.post("/api/v1/explain", json=payload)
    assert response.status_code == 400
    assert response.json()["error"] == "ValidationError"
    assert "risk_assessment_id cannot be empty" in response.json()["detail"]

def test_explain_endpoint_missing_business_context():
    assessment = create_base_assessment_input()
    payload = assessment.model_dump(mode="json")
    # Delete business_context
    del payload["context_evaluation"]["business_context"]
    
    response = client.post("/api/v1/explain", json=payload)
    # FastAPI schema validation returns 422 for missing required fields
    assert response.status_code in (400, 422)

def test_explain_endpoint_missing_asset_context():
    assessment = create_base_assessment_input()
    payload = assessment.model_dump(mode="json")
    del payload["context_evaluation"]["asset_context"]
    
    response = client.post("/api/v1/explain", json=payload)
    assert response.status_code in (400, 422)

def test_explain_endpoint_missing_customer_context():
    assessment = create_base_assessment_input()
    payload = assessment.model_dump(mode="json")
    del payload["context_evaluation"]["customer_context"]
    
    response = client.post("/api/v1/explain", json=payload)
    assert response.status_code in (400, 422)

def test_explain_endpoint_missing_transaction_context():
    assessment = create_base_assessment_input()
    payload = assessment.model_dump(mode="json")
    del payload["context_evaluation"]["transaction_context"]
    
    response = client.post("/api/v1/explain", json=payload)
    assert response.status_code in (400, 422)

def test_explain_endpoint_missing_data_context():
    assessment = create_base_assessment_input()
    payload = assessment.model_dump(mode="json")
    del payload["context_evaluation"]["data_context"]
    
    response = client.post("/api/v1/explain", json=payload)
    assert response.status_code in (400, 422)

def test_explain_endpoint_invalid_prioritization_decision():
    assessment = create_base_assessment_input()
    payload = assessment.model_dump(mode="json")
    # Priority Decision is required, let's remove it
    del payload["prioritization_decision"]
    
    response = client.post("/api/v1/explain", json=payload)
    assert response.status_code in (400, 422)

def test_explain_endpoint_invalid_response_priority():
    assessment = create_base_assessment_input()
    payload = assessment.model_dump(mode="json")
    # Response Priority is required, let's remove it
    del payload["response_priority"]
    
    response = client.post("/api/v1/explain", json=payload)
    assert response.status_code in (400, 422)

def test_swagger_default_example_executes_successfully():
    from app.models.requests import UnifiedRiskAssessment
    example = UnifiedRiskAssessment.model_config["json_schema_extra"]["example"]
    
    response = client.post("/api/v1/explain", json=example)
    assert response.status_code == 200
    
    json_data = response.json()
    assert json_data["report_information"]["risk_assessment_id"] == "URA-20260715-0001"
    assert json_data["report_information"]["incident_id"] == "INC-12345"
    assert json_data["referenced_unified_risk_assessment"]["risk_assessment_id"] == "URA-20260715-0001"
    assert json_data["referenced_unified_risk_assessment"]["incident_classification"]["final_incident_type"] == "Account Takeover"
    assert json_data["referenced_unified_risk_assessment"]["confidence_assessment"]["overall_confidence"] == 0.85

def test_openapi_json_endpoint():
    response = client.get("/openapi.json")
    assert response.status_code == 200
    assert response.json()["openapi"].startswith("3.")
