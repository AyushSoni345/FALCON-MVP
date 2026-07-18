import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import json
import pytest
from fastapi.testclient import TestClient

# Override the output path for test isolation
import Ingestion.config
import Ingestion.core.pipeline
TEST_OUTPUT_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "test_integration_unified_raw_stream.ndjson"))
Ingestion.config.OUTPUT_PATH = TEST_OUTPUT_PATH
Ingestion.core.pipeline.config.OUTPUT_PATH = TEST_OUTPUT_PATH

from Ingestion.api.ingest import app
from Ingestion.collectors.file_collector import FileCollector

@pytest.fixture(autouse=True)
def cleanup_test_file():
    import Ingestion.config
    import Ingestion.core.pipeline
    Ingestion.config.OUTPUT_PATH = TEST_OUTPUT_PATH
    Ingestion.core.pipeline.config.OUTPUT_PATH = TEST_OUTPUT_PATH
    
    if os.path.exists(TEST_OUTPUT_PATH):
        os.remove(TEST_OUTPUT_PATH)
    yield
    if os.path.exists(TEST_OUTPUT_PATH):
        os.remove(TEST_OUTPUT_PATH)

import asyncio
from Ingestion.api.ingest import ingest_endpoint

class MockRequest:
    def __init__(self, json_data):
        self._json_data = json_data

    async def json(self):
        return self._json_data

def test_http_api_ingestion_integration():
    # 1. Post a valid event
    valid_event = {
        "event_id": "integration-uuid-001",
        "event_type": "firewall",
        "source_system": "Perimeter Firewall",
        "timestamp": "2026-07-14T11:00:00Z",
        "severity": "INFO",
        "raw_payload": {
            "firewall_device_id": "FW_TEST_01",
            "source_ip": "192.168.1.50",
            "destination_ip": "10.0.0.1",
            "source_port": 49152,
            "destination_port": 443,
            "protocol": "HTTPS",
            "action": "ALLOW",
            "rule_id": "RULE_HTTPS_ALLOW",
            "interface": "eth0",
            "bytes_sent": 500,
            "bytes_received": 1500
        }
    }
    
    response = asyncio.run(ingest_endpoint(MockRequest(valid_event)))
    assert response.status_code == 202
    res_json = json.loads(response.body.decode('utf-8'))
    assert res_json["status"] == "accepted"
    assert res_json["event_id"] == "integration-uuid-001"
    
    assert os.path.exists(TEST_OUTPUT_PATH)
    with open(TEST_OUTPUT_PATH, "r", encoding="utf-8") as f:
        lines = f.readlines()
        assert len(lines) == 1
        saved_ev = json.loads(lines[0])
        assert saved_ev["metadata"]["original_event_id"] == "integration-uuid-001"

    # 2. Post a duplicate event (should return 400 Bad Request)
    response_dup = asyncio.run(ingest_endpoint(MockRequest(valid_event)))
    assert response_dup.status_code == 400
    res_dup_json = json.loads(response_dup.body.decode('utf-8'))
    assert "Duplicate event rejected" in res_dup_json["error"]

def test_batch_ndjson_ingestion_integration():
    # Construct a temporary mock source ndjson file
    temp_source_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "temp_simulator_events.ndjson"))
    
    events = [
        # Event 1: Valid
        {
            "event_id": "batch-uuid-001",
            "event_type": "firewall",
            "source_system": "Perimeter Firewall",
            "timestamp": "2026-07-14T11:00:00Z",
            "severity": "INFO",
            "raw_payload": {
                "firewall_device_id": "FW_TEST_01",
                "source_ip": "192.168.1.50",
                "destination_ip": "10.0.0.1",
                "source_port": 49152,
                "destination_port": 443,
                "protocol": "HTTPS",
                "action": "ALLOW",
                "rule_id": "RULE_HTTPS_ALLOW",
                "interface": "eth0",
                "bytes_sent": 500,
                "bytes_received": 1500
            }
        },
        # Event 2: Duplicate of 1
        {
            "event_id": "batch-uuid-001",
            "event_type": "firewall",
            "source_system": "Perimeter Firewall",
            "timestamp": "2026-07-14T11:01:00Z",
            "severity": "INFO",
            "raw_payload": {
                "firewall_device_id": "FW_TEST_01",
                "source_ip": "192.168.1.50",
                "destination_ip": "10.0.0.1",
                "source_port": 49152,
                "destination_port": 443,
                "protocol": "HTTPS",
                "action": "ALLOW",
                "rule_id": "RULE_HTTPS_ALLOW",
                "interface": "eth0",
                "bytes_sent": 500,
                "bytes_received": 1500
            }
        },
        # Event 3: Invalid Schema
        {
            "event_id": "batch-uuid-003",
            "event_type": "unknown_type",
            "source_system": "Perimeter Firewall",
            "timestamp": "2026-07-14T11:02:00Z",
            "severity": "INFO",
            "raw_payload": {}
        }
    ]
    
    with open(temp_source_path, "w", encoding="utf-8") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")
            
    try:
        collector = FileCollector(temp_source_path)
        result = collector.process()
        
        assert result["status"] == "success"
        metrics = result["metrics"]
        assert metrics["total_lines"] == 3
        assert metrics["ingested"] == 1
        assert metrics["rejected_duplicate"] == 1
        assert metrics["rejected_schema"] == 1
        
        # Verify output stream contains exactly 1 accepted event
        assert os.path.exists(TEST_OUTPUT_PATH)
        with open(TEST_OUTPUT_PATH, "r", encoding="utf-8") as f:
            saved_lines = f.readlines()
            assert len(saved_lines) == 1
            saved_ev = json.loads(saved_lines[0])
            assert saved_ev["metadata"]["original_event_id"] == "batch-uuid-001"
            
    finally:
        if os.path.exists(temp_source_path):
            os.remove(temp_source_path)
