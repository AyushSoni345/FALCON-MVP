import pytest
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient

from module4.app.main import app
from module4.app.models.models import (
    SecurityGraphEvent,
    EventContext,
    GraphNode,
    GraphRelationship,
    GraphPath,
    GraphMetrics,
    GraphContext,
    GraphStateMetadata,
    ContextEnrichedEvent
)
from module4.app.validators.validators import SecurityGraphEventValidator
from module4.app.exceptions.exceptions import InvalidSecurityGraphEventException
from module4.app.core.container import container

client = TestClient(app)

# Helper function to generate mock event
def create_mock_event(
    event_uuid: str,
    correlation_id: str,
    event_type: str,
    timestamp: datetime,
    primary_entity: str,
    nodes: list = None,
    relationships: list = None
) -> SecurityGraphEvent:
    if nodes is None:
        nodes = [
            GraphNode(node_id="USR-100", node_type="User", properties={"username": "alice"}),
            GraphNode(node_id="DEV-200", node_type="Device", properties={"os": "Windows"}),
            GraphNode(node_id="IP-192.168.10.5", node_type="IP Address", properties={})
        ]
    if relationships is None:
        relationships = [
            GraphRelationship(
                relationship_id="R-1",
                relationship_type="LOGGED_IN_FROM",
                source_node="USR-100",
                target_node="IP-192.168.10.5",
                timestamp=timestamp,
                confidence=0.9,
                relationship_status="Active"
            ),
            GraphRelationship(
                relationship_id="R-2",
                relationship_type="USED_DEVICE",
                source_node="USR-100",
                target_node="DEV-200",
                timestamp=timestamp,
                confidence=0.95,
                relationship_status="Active"
            )
        ]

    return SecurityGraphEvent(
        event_context=EventContext(
            event_uuid=event_uuid,
            correlation_id=correlation_id,
            event_type=event_type,
            event_category="Cyber",
            normalized_timestamp=timestamp,
            source_system="IAM-Portal"
        ),
        graph_nodes=nodes,
        graph_relationships=relationships,
        graph_paths=[
            GraphPath(
                path_id="P-1",
                path_nodes=["USR-100", "IP-192.168.10.5"],
                path_length=1,
                path_type="AuthenticationPath",
                confidence=0.9
            )
        ],
        graph_metrics=GraphMetrics(
            node_degree={"USR-100": 2, "DEV-200": 1, "IP-192.168.10.5": 1},
            relationship_count=2,
            neighbor_count={"USR-100": 2},
            graph_depth=1,
            connected_components=1,
            shortest_path_to_customer=0
        ),
        graph_context=GraphContext(
            primary_entity=primary_entity,
            related_entities=["DEV-200", "IP-192.168.10.5"],
            active_sessions=["SESS-001"],
            linked_transactions=[],
            linked_devices=["DEV-200"],
            linked_ips=["IP-192.168.10.5"],
            linked_beneficiaries=[],
            linked_alerts=[],
            previous_events=[]
        ),
        graph_state_metadata=GraphStateMetadata(
            graph_version="v1.0",
            node_created=3,
            node_updated=0,
            relationships_added=2,
            relationships_updated=0,
            graph_timestamp=timestamp,
            graph_partition="partition-1",
            graph_status="Synched"
        ),
        context_enriched_event=ContextEnrichedEvent(
            original_event={"raw_log": "user login validated"}
        )
    )

# --- VALIDATOR TESTS ---

def test_validator_with_valid_event():
    event = create_mock_event(
        event_uuid="88888888-4444-4444-4444-121212121212",
        correlation_id="CORR-123",
        event_type="IAM Login",
        timestamp=datetime.now(timezone.utc),
        primary_entity="USR-100"
    )
    # Should not raise exception
    SecurityGraphEventValidator.validate_event(event)

def test_validator_with_invalid_uuid():
    event = create_mock_event(
        event_uuid="invalid-uuid-string",
        correlation_id="CORR-123",
        event_type="IAM Login",
        timestamp=datetime.now(timezone.utc),
        primary_entity="USR-100"
    )
    with pytest.raises(InvalidSecurityGraphEventException) as excinfo:
        SecurityGraphEventValidator.validate_event(event)
    assert "not a valid UUID format" in excinfo.value.message

def test_validator_with_dangling_relationship():
    nodes = [GraphNode(node_id="USR-100", node_type="User")]
    relationships = [
        GraphRelationship(
            relationship_id="R-1",
            relationship_type="LOGGED_IN_FROM",
            source_node="USR-100",
            target_node="IP-NONEXISTENT",  # References non-existent target node
            timestamp=datetime.now(timezone.utc),
            confidence=0.9,
            relationship_status="Active"
        )
    ]
    event = create_mock_event(
        event_uuid="88888888-4444-4444-4444-121212121212",
        correlation_id="CORR-123",
        event_type="IAM Login",
        timestamp=datetime.now(timezone.utc),
        primary_entity="USR-100",
        nodes=nodes,
        relationships=relationships
    )
    with pytest.raises(InvalidSecurityGraphEventException) as excinfo:
        SecurityGraphEventValidator.validate_event(event)
    assert "references non-existent target node" in excinfo.value.message

# --- ENGINE UNIT TESTS ---

def test_temporal_engine():
    t0 = datetime.now(timezone.utc)
    e1 = create_mock_event("11111111-1111-1111-1111-111111111111", "COR-1", "IAM Login", t0, "USR-100")
    e2 = create_mock_event("22222222-2222-2222-2222-222222222222", "COR-1", "Beneficiary Added", t0 + timedelta(seconds=10), "USR-100")
    
    res = container.temporal_engine.correlate([e2, e1])  # deliberately pass unordered
    assert res["ordered_events"][0].event_context.event_uuid == e1.event_context.event_uuid
    assert res["duration_seconds"] == 10.0
    assert len(res["temporal_groups"]) == 1
    assert "Immediate/rapid event transition detected" in res["observations"][2]

def test_graph_reasoning_engine():
    t0 = datetime.now(timezone.utc)
    e1 = create_mock_event("11111111-1111-1111-1111-111111111111", "COR-1", "IAM Login", t0, "USR-100")
    
    temporal_res = container.temporal_engine.correlate([e1])
    res = container.graph_engine.reason([e1], temporal_res)
    assert len(res["nodes"]) == 3
    assert len(res["relationships"]) == 2
    assert "USR-100" in [n.node_id for n in res["nodes"]]

def test_pattern_recognition_engine():
    t0 = datetime.now(timezone.utc)
    # Scenario: Account Takeover (Login followed by Beneficiary creation)
    e1 = create_mock_event("11111111-1111-1111-1111-111111111111", "COR-1", "IAM Login", t0, "USR-100")
    e2 = create_mock_event("22222222-2222-2222-2222-222222222222", "COR-1", "Beneficiary Added", t0 + timedelta(seconds=30), "USR-100")
    
    temporal_res = container.temporal_engine.correlate([e1, e2])
    graph_res = container.graph_engine.reason([e1, e2], temporal_res)
    
    res = container.pattern_engine.recognize([e1, e2], temporal_res, graph_res)
    assert "Account Takeover" in res["detected_patterns"]
    assert res["pattern_confidence"] > 0.5

def test_evidence_validator():
    t0 = datetime.now(timezone.utc)
    # Add a node representing Malware
    malware_node = GraphNode(node_id="MAL-1", node_type="Malware", properties={})
    nodes = [
        GraphNode(node_id="DEV-1", node_type="Device"),
        malware_node
    ]
    relationships = [
        GraphRelationship(
            relationship_id="R-10",
            relationship_type="INFECTED_BY",
            source_node="DEV-1",
            target_node="MAL-1",
            timestamp=t0,
            confidence=0.9,
            relationship_status="anomaly"
        )
    ]
    e1 = create_mock_event("11111111-1111-1111-1111-111111111111", "COR-1", "Malware Alert", t0, "DEV-1", nodes, relationships)
    
    temporal_res = container.temporal_engine.correlate([e1])
    graph_res = container.graph_engine.reason([e1], temporal_res)
    sequence_res = container.attack_sequence_engine.reconstruct([e1], temporal_res, graph_res, {})
    
    res = container.evidence_validator.validate_evidence([e1], sequence_res, graph_res)
    assert "MAL-1" in res["malware_matches"]
    assert res["evidence_score"] > 0.4
    assert res["validation_status"] == "VALID"

def test_confidence_scoring_engine():
    t0 = datetime.now(timezone.utc)
    e1 = create_mock_event("11111111-1111-1111-1111-111111111111", "COR-1", "IAM Login", t0, "USR-100")
    
    temporal_res = container.temporal_engine.correlate([e1])
    graph_res = container.graph_engine.reason([e1], temporal_res)
    sequence_res = container.attack_sequence_engine.reconstruct([e1], temporal_res, graph_res, {})
    evidence_res = container.evidence_validator.validate_evidence([e1], sequence_res, graph_res)
    hypotheses = container.hypothesis_generator.generate_hypotheses([e1], evidence_res)
    
    res = container.confidence_engine.calculate_confidence([e1], evidence_res, hypotheses)
    assert 0.0 <= res["overall_confidence"] <= 1.0
    assert "temporal_confidence" in res
    assert "graph_confidence" in res

def test_incident_builder():
    t0 = datetime.now(timezone.utc)
    e1 = create_mock_event("11111111-1111-1111-1111-111111111111", "COR-1", "IAM Login", t0, "USR-100")
    
    temporal_res = container.temporal_engine.correlate([e1])
    graph_res = container.graph_engine.reason([e1], temporal_res)
    patterns_res = container.pattern_engine.recognize([e1], temporal_res, graph_res)
    sequence_res = container.attack_sequence_engine.reconstruct([e1], temporal_res, graph_res, patterns_res)
    evidence_res = container.evidence_validator.validate_evidence([e1], sequence_res, graph_res)
    hypotheses = container.hypothesis_generator.generate_hypotheses([e1], evidence_res)
    confidence_res = container.confidence_engine.calculate_confidence([e1], evidence_res, hypotheses)

    incident = container.incident_builder.build_incident(
        events=[e1],
        temporal_output=temporal_res,
        graph_output=graph_res,
        patterns_output=patterns_res,
        sequence_output=sequence_res,
        evidence_output=evidence_res,
        hypotheses=hypotheses,
        confidence_output=confidence_res
    )
    
    assert incident.incident_info.incident_id.startswith("INC-")
    assert incident.incident_info.correlated_event_count == 1
    assert len(incident.referenced_security_graph_events) == 1

# --- END-TO-END REPOSITORY & API TESTS ---

def test_incident_repository():
    container.incident_repository.clear()
    t0 = datetime.now(timezone.utc)
    e1 = create_mock_event("11111111-1111-1111-1111-111111111111", "COR-1", "IAM Login", t0, "USR-100")
    
    # Build incident
    temporal_res = container.temporal_engine.correlate([e1])
    graph_res = container.graph_engine.reason([e1], temporal_res)
    patterns_res = container.pattern_engine.recognize([e1], temporal_res, graph_res)
    sequence_res = container.attack_sequence_engine.reconstruct([e1], temporal_res, graph_res, patterns_res)
    evidence_res = container.evidence_validator.validate_evidence([e1], sequence_res, graph_res)
    hypotheses = container.hypothesis_generator.generate_hypotheses([e1], evidence_res)
    confidence_res = container.confidence_engine.calculate_confidence([e1], evidence_res, hypotheses)

    incident = container.incident_builder.build_incident(
        events=[e1],
        temporal_output=temporal_res,
        graph_output=graph_res,
        patterns_output=patterns_res,
        sequence_output=sequence_res,
        evidence_output=evidence_res,
        hypotheses=hypotheses,
        confidence_output=confidence_res
    )

    # Save
    container.incident_repository.save(incident)
    assert len(container.incident_repository.list_all()) == 1
    
    # Retrieve
    retrieved = container.incident_repository.get(incident.incident_info.incident_id)
    assert retrieved is not None
    assert retrieved.incident_info.primary_entity == "USR-100"

def test_api_e2e_correlation():
    t0 = datetime.now(timezone.utc).isoformat()
    # Construct raw payload matching the SecurityGraphEvent model structure
    payload = {
        "event_context": {
            "event_uuid": "55555555-5555-5555-5555-555555555555",
            "correlation_id": "COR-E2E-1",
            "event_type": "IAM Login",
            "event_category": "Cyber",
            "normalized_timestamp": t0,
            "source_system": "IAM-Core"
        },
        "graph_nodes": [
            {"node_id": "USR-E2E", "node_type": "User", "properties": {}},
            {"node_id": "IP-E2E", "node_type": "IP Address", "properties": {}}
        ],
        "graph_relationships": [
            {
                "relationship_id": "REL-E2E",
                "relationship_type": "LOGGED_IN_FROM",
                "source_node": "USR-E2E",
                "target_node": "IP-E2E",
                "timestamp": t0,
                "confidence": 0.95,
                "relationship_status": "Active"
            }
        ],
        "graph_paths": [
            {
                "path_id": "PATH-E2E",
                "path_nodes": ["USR-E2E", "IP-E2E"],
                "path_length": 1,
                "path_type": "AuthPath",
                "confidence": 0.95
            }
        ],
        "graph_metrics": {
            "node_degree": {"USR-E2E": 1, "IP-E2E": 1},
            "relationship_count": 1,
            "neighbor_count": {"USR-E2E": 1},
            "graph_depth": 1,
            "connected_components": 1,
            "shortest_path_to_customer": 0
        },
        "graph_context": {
            "primary_entity": "USR-E2E",
            "related_entities": ["IP-E2E"],
            "active_sessions": [],
            "linked_transactions": [],
            "linked_devices": [],
            "linked_ips": ["IP-E2E"],
            "linked_beneficiaries": [],
            "linked_alerts": [],
            "previous_events": []
        },
        "graph_state_metadata": {
            "graph_version": "v1",
            "node_created": 2,
            "node_updated": 0,
            "relationships_added": 1,
            "relationships_updated": 0,
            "graph_timestamp": t0,
            "graph_partition": "p1",
            "graph_status": "Synched"
        },
        "context_enriched_event": {
            "original_event": {}
        }
    }

    # Call POST API to correlate
    response = client.post("/api/v1/correlate", json=payload)
    assert response.status_code == 201
    
    data = response.json()
    assert "incident_info" in data
    assert data["incident_info"]["incident_id"].startswith("INC-")
    assert data["incident_info"]["primary_entity"] == "USR-E2E"
    assert data["incident_info"]["correlated_event_count"] == 1
    
    # Verify we can list it
    get_all_response = client.get("/api/v1/incidents")
    assert get_all_response.status_code == 200
    assert len(get_all_response.json()) >= 1
