import pytest
from module5.engines.behaviour.engine import BehaviourAnalyticsEngine
from module5.engines.fraud.engine import FraudAnalyticsEngine
from module5.engines.cyber.engine import CyberThreatAnalyticsEngine
from module5.engines.quantum.engine import QuantumRiskAnalyticsEngine
from module5.models.shared.engine_result import EngineStatus

@pytest.mark.asyncio
async def test_behaviour_engine_active(mock_behaviour_incident):
    engine = BehaviourAnalyticsEngine()
    result = await engine.analyze(mock_behaviour_incident, [])
    assert result.engine_name == "Behaviour"
    assert result.status == EngineStatus.ACTIVE
    assert result.risk_score > 50.0
    assert result.behaviour_assessment is not None
    assert "Impossible Travel" in [a["anomaly_type"] for a in result.behaviour_assessment["behavioural_anomalies"]]

@pytest.mark.asyncio
async def test_behaviour_engine_no_findings():
    from module5.tests.conftest import create_base_incident
    # Incident with normal logs, no behavioral anomalies
    incident = create_base_incident(behavioral_anomalies=[], anomaly_summary="User logged in normally.")
    engine = BehaviourAnalyticsEngine()
    result = await engine.analyze(incident, [])
    assert result.status == EngineStatus.NO_SIGNIFICANT_FINDINGS

@pytest.mark.asyncio
async def test_fraud_engine_active(mock_fraud_incident):
    engine = FraudAnalyticsEngine()
    result = await engine.analyze(mock_fraud_incident, [])
    assert result.engine_name == "Fraud"
    assert result.status == EngineStatus.ACTIVE
    assert result.risk_score > 50.0
    assert result.fraud_assessment is not None
    assert len(result.fraud_assessment["suspicious_transactions"]) > 0

@pytest.mark.asyncio
async def test_cyber_engine_active(mock_cyber_incident):
    engine = CyberThreatAnalyticsEngine()
    result = await engine.analyze(mock_cyber_incident, [])
    assert result.engine_name == "Cyber"
    assert result.status == EngineStatus.ACTIVE
    assert result.risk_score > 50.0
    assert result.cyber_assessment is not None
    assert "Credential Theft" in result.cyber_assessment["detected_attack_pattern"]

@pytest.mark.asyncio
async def test_quantum_engine_active(mock_quantum_incident):
    engine = QuantumRiskAnalyticsEngine()
    result = await engine.analyze(mock_quantum_incident, [])
    assert result.engine_name == "Quantum"
    assert result.status == EngineStatus.ACTIVE
    assert result.risk_score > 50.0
    assert result.quantum_assessment is not None
    assert len(result.quantum_assessment["HNDL_indicators"]) > 0
