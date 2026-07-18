import pytest
from fastapi.testclient import TestClient
from module5.main import app
from module5.tests.conftest import create_base_incident

client = TestClient(app)

def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"

def test_analyze_endpoint_validation_error():
    # Payload with missing incident_id
    incident = create_base_incident()
    incident.incident_information.incident_id = ""
    
    response = client.post("/module5/analyze", json=incident.model_dump(mode="json"))
    assert response.status_code == 400
    assert response.json()["error"] == "ValidationError"
    assert "Missing incident_id" in response.json()["detail"]

def test_analyze_endpoint_success():
    incident = create_base_incident()
    # Add a simple behavioral anomaly so Behaviour is active
    incident.correlated_evidence.behavioral_anomalies = ["Impossible Travel"]
    
    response = client.post("/module5/analyze", json=incident.model_dump(mode="json"))
    assert response.status_code == 200
    
    json_data = response.json()
    assert "assessment_information" in json_data
    assert "active_domain_assessments" in json_data
    
    active_assessments = json_data["active_domain_assessments"]
    assert "behaviour_assessment" in active_assessments
    
    # Verify inactive domains are NOT in the Active Domain Assessments at all (not even null)
    assert "fraud_assessment" not in active_assessments
    assert "cyber_assessment" not in active_assessments
    assert "quantum_assessment" not in active_assessments
