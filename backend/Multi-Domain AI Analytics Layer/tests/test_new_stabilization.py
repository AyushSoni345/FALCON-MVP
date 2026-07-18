import pytest
from datetime import datetime, timezone, timedelta
from module5.tests.conftest import create_base_incident
from module5.models.input.incident import TimelineStep, GraphNode, AttackGraph
from module5.engines.fraud.engine import FraudAnalyticsEngine
from module5.engines.quantum.engine import QuantumRiskAnalyticsEngine
from module5.engines.cyber.engine import CyberThreatAnalyticsEngine
from module5.engines.behaviour.engine import BehaviourAnalyticsEngine
from module5.intelligence.manager import CrossDomainIntelligenceManager, classify_signal, SignalCategory
from module5.models.shared.engine_result import EngineStatus, EngineResult
from module5.orchestrator.orchestrator import Module5Orchestrator

@pytest.mark.asyncio
async def test_atm_upi_correlation():
    # Create timeline with ATM withdrawal followed by UPI transfer within 3 minutes
    t0 = datetime.now(timezone.utc)
    timeline = [
        TimelineStep(sequence_number=1, timestamp=t0, event_uuid="evt-atm", action="ATM_WITHDRAWAL", entity="USR-ATM-1", confidence=0.9),
        TimelineStep(sequence_number=2, timestamp=t0 + timedelta(minutes=3), event_uuid="evt-upi", action="UPI_TRANSFER", entity="USR-ATM-1", confidence=0.9)
    ]
    incident = create_base_incident(incident_id="INC-ATM-UPI", incident_type="ATM UPI Correlation Test", category="Financial", timeline=timeline)
    engine = FraudAnalyticsEngine()
    result = await engine.analyze(incident, [])
    assert result.status == EngineStatus.ACTIVE
    assert any("ATM Withdrawal followed by rapid UPI Transfer" in tx["risk_reason"] for tx in result.fraud_assessment["suspicious_transactions"])
    assert "ATM-to-UPI Cashout Correlation" in result.fraud_assessment["fraud_patterns"]

@pytest.mark.asyncio
async def test_long_lived_encrypted_sessions():
    t0 = datetime.now(timezone.utc)
    timeline = [
        TimelineStep(sequence_number=1, timestamp=t0, event_uuid="evt-ssh", action="SSH_SESSION_ESTABLISHED", entity="SSH-SRV-1", confidence=0.9)
    ]
    nodes = [
        GraphNode(node_id="SSH-SRV-1", node_type="SSH", properties={"duration": 90000, "status": "long-lived"})
    ]
    incident = create_base_incident(incident_id="INC-SSH-LONG", incident_type="Quantum Long Lived Session Test", category="Quantum", timeline=timeline, nodes=nodes)
    engine = QuantumRiskAnalyticsEngine()
    result = await engine.analyze(incident, [])
    assert result.status == EngineStatus.ACTIVE
    assert any(ind["indicator_type"] == "Long-Lived Encrypted Session" for ind in result.quantum_assessment["HNDL_indicators"])

def test_signal_classification():
    assert classify_signal("Cyber shared: Credential Compromise Detected") == SignalCategory.CREDENTIAL_COMPROMISE
    assert classify_signal("Behaviour shared: Concurrent Session Activity") == SignalCategory.SESSION_ABUSE
    assert classify_signal("Fraud shared: Mule Account Suspicion") == SignalCategory.MULE_ACCOUNT
    assert classify_signal("Quantum shared: Bulk Encrypted Data Transfer Detected") == SignalCategory.BULK_ENCRYPTED_TRANSFER

@pytest.mark.asyncio
async def test_cyber_to_fraud_routing():
    t0 = datetime.now(timezone.utc)
    # Fraud engine run with Cyber external signals (Credential Compromise) should amplify Fraud score
    incident = create_base_incident(
        incident_id="INC-FRD-CYB", 
        incident_type="Financial Fraud", 
        category="Financial", 
        timeline=[
            TimelineStep(sequence_number=1, timestamp=t0, event_uuid="evt-1", action="TRANSFER_INITIATED", entity="USR-MOCK", confidence=0.9)
        ],
        affected_accounts=["ACC-SAVINGS-01"]
    )
    engine = FraudAnalyticsEngine()
    
    # Run without signals
    res_no_sig = await engine.analyze(incident, [])
    # Run with cyber signal
    res_with_sig = await engine.analyze(incident, ["Cyber shared: Credential Compromise Detected"])
    
    assert res_with_sig.risk_score > res_no_sig.risk_score
    assert res_with_sig.confidence > res_no_sig.confidence

@pytest.mark.asyncio
async def test_fraud_to_behaviour_routing():
    t0 = datetime.now(timezone.utc)
    # Behaviour engine run with Fraud external signals (Account Takeover Suspicion) should amplify Behaviour score
    incident = create_base_incident(
        incident_id="INC-BEH-FRD",
        incident_type="Anomalous Behaviour",
        category="Cyber",
        timeline=[
            TimelineStep(sequence_number=1, timestamp=t0, event_uuid="evt-1", action="LOGIN", entity="USR-MOCK", confidence=0.9)
        ],
        behavioral_anomalies=["Impossible Travel"]
    )
    engine = BehaviourAnalyticsEngine()
    
    # Run without signals
    res_no_sig = await engine.analyze(incident, [])
    # Run with fraud signal
    res_with_sig = await engine.analyze(incident, ["Fraud shared: Account Takeover Suspicion"])
    
    assert res_with_sig.risk_score > res_no_sig.risk_score
    assert res_with_sig.confidence > res_no_sig.confidence

@pytest.mark.asyncio
async def test_fraud_to_cyber_routing():
    t0 = datetime.now(timezone.utc)
    # Cyber engine run with Fraud external signals (Account Takeover Suspicion) should amplify Cyber score
    incident = create_base_incident(
        incident_id="INC-CYB-FRD",
        incident_type="Infrastructure Exploit",
        category="Cyber",
        timeline=[
            TimelineStep(sequence_number=1, timestamp=t0, event_uuid="evt-1", action="VPN_LOGIN", entity="USR-MOCK", confidence=0.9)
        ],
        supporting_patterns=["Credential Theft"],
        malware_matches=["GenericMalware"]
    )
    engine = CyberThreatAnalyticsEngine()
    
    # Run without signals
    res_no_sig = await engine.analyze(incident, [])
    # Run with fraud signal
    res_with_sig = await engine.analyze(incident, ["Fraud shared: Account Takeover Suspicion"])
    
    assert res_with_sig.risk_score > res_no_sig.risk_score
    assert res_with_sig.confidence > res_no_sig.confidence

@pytest.mark.asyncio
async def test_quantum_to_cyber_routing():
    t0 = datetime.now(timezone.utc)
    # Cyber engine run with Quantum external signals (Bulk Encrypted Transfer) should amplify Cyber score
    incident = create_base_incident(
        incident_id="INC-CYB-QTM",
        incident_type="Infrastructure Exploit",
        category="Cyber",
        timeline=[
            TimelineStep(sequence_number=1, timestamp=t0, event_uuid="evt-1", action="VPN_LOGIN", entity="USR-MOCK", confidence=0.9)
        ],
        supporting_patterns=["Credential Theft"],
        malware_matches=["GenericMalware"]
    )
    engine = CyberThreatAnalyticsEngine()
    
    # Run without signals
    res_no_sig = await engine.analyze(incident, [])
    # Run with quantum signal
    res_with_sig = await engine.analyze(incident, ["Quantum shared: Bulk Encrypted Data Transfer Detected"])
    
    assert res_with_sig.risk_score > res_no_sig.risk_score
    assert res_with_sig.confidence > res_no_sig.confidence
