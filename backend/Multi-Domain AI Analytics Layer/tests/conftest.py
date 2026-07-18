import pytest
from datetime import datetime, timezone
from typing import List
from module5.models.input.incident import (
    CorrelatedSecurityIncident,
    IncidentInformation,
    TimelineStep,
    CorrelatedEvidence,
    AttackGraph,
    AIReasoning,
    ThreatHypothesis,
    ConfidenceAssessment,
    IncidentContext,
    InvestigationContext,
    ReferencedSecurityGraphEvent,
    PredictiveIntelligence,
    GraphNode,
    GraphRelationship
)

def create_base_incident(
    incident_id: str = "INC-12345",
    incident_type: str = "Account Takeover",
    category: str = "Hybrid",
    timeline: List[TimelineStep] = None,
    behavioral_anomalies: List[str] = None,
    malware_matches: List[str] = None,
    ioc_matches: List[str] = None,
    supporting_patterns: List[str] = None,
    anomaly_summary: str = "Normal activity.",
    nodes: List[GraphNode] = None,
    active_sessions: List[str] = None,
    affected_devices: List[str] = None,
    affected_accounts: List[str] = None,
    affected_servers: List[str] = None
) -> CorrelatedSecurityIncident:
    
    if not timeline:
        timeline = [
            TimelineStep(
                sequence_number=1,
                timestamp=datetime.now(timezone.utc),
                event_uuid="evt-0001",
                action="LOGIN",
                entity="USR-MOCK",
                confidence=0.9
            )
        ]
        
    return CorrelatedSecurityIncident(
        incident_information=IncidentInformation(
            incident_id=incident_id,
            incident_type=incident_type,
            incident_category=category,
            incident_status="Active",
            incident_start_time=datetime.now(timezone.utc),
            incident_end_time=datetime.now(timezone.utc),
            incident_duration=10.0,
            primary_entity="USR-MOCK",
            affected_assets=1,
            correlated_event_count=len(timeline)
        ),
        incident_timeline=timeline,
        correlated_evidence=CorrelatedEvidence(
            related_events=[step.event_uuid for step in timeline],
            behavioral_anomalies=behavioral_anomalies or [],
            malware_matches=malware_matches or [],
            IOC_matches=ioc_matches or []
        ),
        attack_graph=AttackGraph(
            attack_nodes=nodes or [GraphNode(node_id="USR-MOCK", node_type="User")],
            attack_relationships=[],
            attack_entry_point="192.168.10.5",
            attack_exit_point="SRV-LEDGER",
            lateral_movements=[]
        ),
        ai_reasoning=AIReasoning(
            reasoning_chain=["Step 1 observed."],
            supporting_patterns=supporting_patterns or [],
            graph_observations=[],
            temporal_observations=[],
            anomaly_summary=anomaly_summary,
            relationship_summary="User connected to IP."
        ),
        threat_hypotheses=[
            ThreatHypothesis(
                hypothesis_id="HYP-001",
                hypothesis_type="Credential Theft",
                description="User account credentials stolen.",
                supporting_evidence=[],
                contradictory_evidence=[],
                likelihood=0.8
            )
        ],
        confidence_assessment=ConfidenceAssessment(
            overall_confidence=0.8,
            temporal_confidence=0.8,
            graph_confidence=0.8,
            behavioral_confidence=0.8,
            threat_intelligence_confidence=0.8,
            fraud_confidence=0.8,
            evidence_score=0.8,
            uncertainty_score=0.2
        ),
        incident_context=IncidentContext(
            affected_customers=["CUST-999"],
            affected_employees=[],
            affected_accounts=affected_accounts or [],
            affected_transactions=[],
            affected_devices=affected_devices or [],
            affected_servers=affected_servers or [],
            affected_applications=[],
            business_process="Retail Transfers"
        ),
        investigation_context=InvestigationContext(
            first_observed_event=datetime.now(timezone.utc),
            latest_event=datetime.now(timezone.utc),
            historical_similarity=0.4
        ),
        predictive_intelligence=PredictiveIntelligence(predictions_enabled=False),
        referenced_security_graph_events=[]
    )

@pytest.fixture
def mock_behaviour_incident():
    timeline = [
        TimelineStep(sequence_number=1, timestamp=datetime.now(timezone.utc), event_uuid="evt-0001", action="LOGIN", entity="USR-MOCK", confidence=0.9),
        TimelineStep(sequence_number=2, timestamp=datetime.now(timezone.utc), event_uuid="evt-0002", action="FAILED_AUTH", entity="USR-MOCK", confidence=0.9)
    ]
    return create_base_incident(
        incident_id="INC-BEH-99",
        incident_type="Anomalous Behaviour",
        category="Cyber",
        timeline=timeline,
        behavioral_anomalies=["Impossible Travel", "Concurrent Sessions"],
        anomaly_summary="User logged in from two distant locations within 5 minutes.",
        affected_devices=["DEV-UNTRUSTED"]
    )

@pytest.fixture
def mock_fraud_incident():
    timeline = [
        TimelineStep(sequence_number=1, timestamp=datetime.now(timezone.utc), event_uuid="evt-0001", action="BENEFICIARY_CREATE", entity="USR-MOCK", confidence=0.9),
        TimelineStep(sequence_number=2, timestamp=datetime.now(timezone.utc), event_uuid="evt-0002", action="TRANSFER_INITIATED", entity="USR-MOCK", confidence=0.9)
    ]
    return create_base_incident(
        incident_id="INC-FRD-99",
        incident_type="Financial Fraud",
        category="Financial",
        timeline=timeline,
        anomaly_summary="High-value transfer of ₹5,00,000 executed immediately after creating beneficiary.",
        affected_accounts=["ACC-SAVINGS-01"]
    )

@pytest.fixture
def mock_cyber_incident():
    timeline = [
        TimelineStep(sequence_number=1, timestamp=datetime.now(timezone.utc), event_uuid="evt-0001", action="VPN_LOGIN", entity="USR-MOCK", confidence=0.9),
        TimelineStep(sequence_number=2, timestamp=datetime.now(timezone.utc), event_uuid="evt-0002", action="ADMIN_PROCESS_SPAWNED", entity="USR-MOCK", confidence=0.9)
    ]
    return create_base_incident(
        incident_id="INC-CYB-99",
        incident_type="Infrastructure Exploit",
        category="Cyber",
        timeline=timeline,
        malware_matches=["Emotet"],
        ioc_matches=["C2-IP-Malicious"],
        supporting_patterns=["Credential Theft", "Lateral Movement"],
        anomaly_summary="Lateral movement detected from employee laptop to VPN Gateway and server CA.",
        nodes=[
            GraphNode(node_id="Employee Laptop", node_type="Device", properties={"severity": "MEDIUM", "name": "LAP-EMP-01"}),
            GraphNode(node_id="VPN Gateway", node_type="Gateway", properties={"severity": "HIGH"})
        ]
    )

@pytest.fixture
def mock_quantum_incident():
    timeline = [
        TimelineStep(sequence_number=1, timestamp=datetime.now(timezone.utc), event_uuid="evt-0001", action="ARCHIVE_EXPLAIN_READ", entity="USR-MOCK", confidence=0.9),
        TimelineStep(sequence_number=2, timestamp=datetime.now(timezone.utc), event_uuid="evt-0002", action="BULK_EXFILTRATION_OUTBOUND", entity="USR-MOCK", confidence=0.9)
    ]
    return create_base_incident(
        incident_id="INC-QTM-99",
        incident_type="Harvest Now Decrypt Later",
        category="Quantum",
        timeline=timeline,
        anomaly_summary="Mass encrypted exfiltration of 5GB from historical backups CA repository.",
        nodes=[
            GraphNode(node_id="Backup DB", node_type="CryptographicAsset", properties={"algorithm": "RSA-2048", "crypto_category": "Asymmetric", "bytes_sent": 5200000000})
        ],
        affected_servers=["SRV-BACKUP"]
    )
