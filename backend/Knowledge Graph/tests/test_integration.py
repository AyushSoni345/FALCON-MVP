import pytest
import asyncio
from src.main import create_app
from src.models.input_event import ContextEnrichedEvent

@pytest.fixture
def ingress_app():
    return create_app()

@pytest.mark.asyncio
async def test_full_pipeline(ingress_app):
    event_payload = {
        "event_uuid": "evt-001",
        "correlation_id": "corr-001",
        "timestamp": "2023-10-27T10:00:00Z",
        "Identity Context": {
            "customer_id": "cust-123",
            "user_id": "usr-456"
        },
        "Device Context": {
            "device_id": "dev-789"
        },
        "Network Context": {
            "source_ip": "192.168.1.10"
        }
    }
    
    event = ContextEnrichedEvent(**event_payload)
    
    # Process event 1
    result = await ingress_app.processor(event)
    
    assert result is not None
    # Customer, User, Device, IP, Event = 5 nodes
    assert len(result.graph_nodes) == 5
    
    assert result.graph_state_metadata.total_nodes == 5
    
    # Process event 2 (same entities, new IP, new Event node)
    event_payload_2 = dict(event_payload)
    event_payload_2["event_uuid"] = "evt-002"
    event_payload_2["Network Context"] = {"source_ip": "10.0.0.5"} # New IP
    
    event_2 = ContextEnrichedEvent(**event_payload_2)
    result_2 = await ingress_app.processor(event_2)
    
    # Total nodes should be 5 + 1 (new IP) + 1 (new Event) = 7
    assert result_2.graph_state_metadata.total_nodes == 7
    
    # Node observation count should increase
    cust_node = next(n for n in result_2.graph_nodes if n.node_type == "Customer")
    assert cust_node.observation_count == 2
    assert cust_node.version == 2
