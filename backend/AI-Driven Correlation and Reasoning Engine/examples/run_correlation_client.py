import requests
from datetime import datetime

def run_sample_correlation():
    # Base url of the FastAPI service
    url = "http://127.0.0.1:8000/api/v1/correlate"
    
    t0 = datetime.utcnow().isoformat() + "Z"
    
    # Define a sample SecurityGraphEvent representing a suspicious transfer scenario
    event_payload = {
        "event_context": {
            "event_uuid": "f3ab0cde-1234-5678-abcd-ef1234567890",
            "correlation_id": "CORR-DEMO-99",
            "event_type": "IAM Login",
            "event_category": "Cyber",
            "normalized_timestamp": t0,
            "source_system": "IAM-Core"
        },
        "graph_nodes": [
            {"node_id": "USR-BOB", "node_type": "User", "properties": {"name": "Bob Smith"}},
            {"node_id": "DEV-IPAD", "node_type": "Device", "properties": {"os": "iOS"}},
            {"node_id": "IP-10.20.30.40", "node_type": "IP Address", "properties": {}},
            {"node_id": "BENEFICIARY-HACKER", "node_type": "Beneficiary", "properties": {"is_flagged": True}}
        ],
        "graph_relationships": [
            {
                "relationship_id": "REL-1",
                "relationship_type": "LOGGED_IN_FROM",
                "source_node": "USR-BOB",
                "target_node": "IP-10.20.30.40",
                "timestamp": t0,
                "confidence": 0.95,
                "relationship_status": "anomaly"
            },
            {
                "relationship_id": "REL-2",
                "relationship_type": "USED_DEVICE",
                "source_node": "USR-BOB",
                "target_node": "DEV-IPAD",
                "timestamp": t0,
                "confidence": 0.9,
                "relationship_status": "Active"
            }
        ],
        "graph_paths": [
            {
                "path_id": "PATH-1",
                "path_nodes": ["USR-BOB", "IP-10.20.30.40"],
                "path_length": 1,
                "path_type": "AuthPath",
                "confidence": 0.95
            }
        ],
        "graph_metrics": {
            "node_degree": {"USR-BOB": 2, "DEV-IPAD": 1, "IP-10.20.30.40": 1},
            "relationship_count": 2,
            "neighbor_count": {"USR-BOB": 2},
            "graph_depth": 1,
            "connected_components": 1,
            "shortest_path_to_customer": 0
        },
        "graph_context": {
            "primary_entity": "USR-BOB",
            "related_entities": ["DEV-IPAD", "IP-10.20.30.40"],
            "active_sessions": ["SESS-BOB-9"],
            "linked_transactions": [],
            "linked_devices": ["DEV-IPAD"],
            "linked_ips": ["IP-10.20.30.40"],
            "linked_beneficiaries": ["BENEFICIARY-HACKER"],
            "linked_alerts": [],
            "previous_events": []
        },
        "graph_state_metadata": {
            "graph_version": "v1.2",
            "node_created": 4,
            "node_updated": 0,
            "relationships_added": 2,
            "relationships_updated": 0,
            "graph_timestamp": t0,
            "graph_partition": "p99",
            "graph_status": "Synched"
        },
        "context_enriched_event": {
            "original_event": {"details": "Bob login from unexpected location"}
        }
    }

    print("Sending SecurityGraphEvent to correlation engine...")
    try:
        response = requests.post(url, json=event_payload)
        if response.status_code == 201:
            data = response.json()
            print("\n--- Correlation Result ---")
            print(f"Incident ID: {data['incident_info']['incident_id']}")
            print(f"Incident Type: {data['incident_info']['incident_type']}")
            print(f"Incident Category: {data['incident_info']['incident_category']}")
            print(f"Primary Entity: {data['incident_info']['primary_entity']}")
            print(f"Overall Confidence: {data['confidence_assessment']['overall_confidence']}")
            print(f"Detected Patterns: {data['ai_reasoning']['supporting_patterns']}")
            print(f"Timeline Steps: {len(data['incident_timeline'])}")
            print("--------------------------\n")
        else:
            print(f"Failed with status code {response.status_code}: {response.text}")
    except requests.exceptions.ConnectionError:
        print("Could not connect to the API server. Please start the server using 'uvicorn app.main:app --reload' first.")

if __name__ == "__main__":
    run_sample_correlation()
