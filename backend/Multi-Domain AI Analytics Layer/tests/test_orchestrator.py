import pytest
from module5.orchestrator.orchestrator import Module5Orchestrator
from module5.models.output.assessment import DomainAIAssessment
from module5.tests.conftest import create_base_incident

@pytest.mark.asyncio
async def test_orchestrator_hybrid_flow(mock_behaviour_incident):
    orchestrator = Module5Orchestrator()
    # Mocking behaviour incident which is a hybrid case
    assessment = await orchestrator.analyze(mock_behaviour_incident)
    
    assert isinstance(assessment, DomainAIAssessment)
    assert assessment.assessment_information.incident_id == mock_behaviour_incident.incident_information.incident_id
    assert "Behaviour" in assessment.assessment_information.active_domains
    
    # Verify Behaviour assessment is populated inside Active Domain Assessments
    assert assessment.active_domain_assessments is not None
    assert assessment.active_domain_assessments.behaviour_assessment is not None
    # Verify other inactive engines are None (omitted)
    assert assessment.active_domain_assessments.fraud_assessment is None
    assert assessment.active_domain_assessments.cyber_assessment is None
    assert assessment.active_domain_assessments.quantum_assessment is None

@pytest.mark.asyncio
async def test_orchestrator_financial_flow(mock_fraud_incident):
    orchestrator = Module5Orchestrator()
    assessment = await orchestrator.analyze(mock_fraud_incident)
    
    assert isinstance(assessment, DomainAIAssessment)
    assert "Fraud" in assessment.assessment_information.active_domains
    assert assessment.active_domain_assessments is not None
    assert assessment.active_domain_assessments.fraud_assessment is not None
    assert assessment.active_domain_assessments.behaviour_assessment is None
    assert assessment.active_domain_assessments.cyber_assessment is None
    assert assessment.active_domain_assessments.quantum_assessment is None

@pytest.mark.asyncio
async def test_orchestrator_quantum_flow(mock_quantum_incident):
    orchestrator = Module5Orchestrator()
    assessment = await orchestrator.analyze(mock_quantum_incident)
    
    assert isinstance(assessment, DomainAIAssessment)
    assert "Quantum" in assessment.assessment_information.active_domains
    assert assessment.active_domain_assessments is not None
    assert assessment.active_domain_assessments.quantum_assessment is not None
    assert assessment.active_domain_assessments.behaviour_assessment is None
    assert assessment.active_domain_assessments.fraud_assessment is None
    assert assessment.active_domain_assessments.cyber_assessment is None
