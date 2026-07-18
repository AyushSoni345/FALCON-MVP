import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import json
import pytest
from datetime import datetime

# Override the output path for test isolation before importing pipeline
import Ingestion.config
TEST_OUTPUT_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "test_unified_raw_stream.ndjson"))
Ingestion.config.OUTPUT_PATH = TEST_OUTPUT_PATH

from Ingestion.core.pipeline import IngestionPipeline
from Ingestion.core.validator import validate_event

@pytest.fixture(autouse=True)
def cleanup_test_file():
    """Removes the test output file before and after each test."""
    import Ingestion.config
    import Ingestion.core.pipeline
    Ingestion.config.OUTPUT_PATH = TEST_OUTPUT_PATH
    Ingestion.core.pipeline.config.OUTPUT_PATH = TEST_OUTPUT_PATH
    
    if os.path.exists(TEST_OUTPUT_PATH):
        os.remove(TEST_OUTPUT_PATH)
    yield
    if os.path.exists(TEST_OUTPUT_PATH):
        os.remove(TEST_OUTPUT_PATH)

def test_schema_and_mandatory_validation():
    # Setup fresh pipeline
    pipeline = IngestionPipeline()
    
    # 1. Valid event check
    valid_event = {
        "event_id": "8c54324f-ef76-46b7-a3f1-4dbfa7f8841a",
        "event_type": "firewall",
        "source_system": "Perimeter Firewall",
        "timestamp": "2026-07-14T11:00:00Z",
        "severity": "INFO",
        "session_id": "SESS_TEST_01",
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
            "bytes_received": 1500,
            "session_id": "SESS_TEST_01"
        }
    }
    
    success, err_msg, payload = pipeline.ingest_event(valid_event)
    assert success is True, f"Failed valid event ingestion: {err_msg}"
    assert payload["status"] == "accepted"
    assert payload["event_id"] == valid_event["event_id"]

    # 2. Invalid event type
    invalid_type_event = valid_event.copy()
    invalid_type_event["event_id"] = "8c54324f-ef76-46b7-a3f1-4dbfa7f8841b"
    invalid_type_event["event_type"] = "unknown_type"
    success, err_msg, _ = pipeline.ingest_event(invalid_type_event)
    assert success is False
    assert "Unknown event_type" in err_msg

    # 3. Missing envelope fields
    missing_fields_event = valid_event.copy()
    missing_fields_event["event_id"] = ""
    success, err_msg, _ = pipeline.ingest_event(missing_fields_event)
    assert success is False
    assert "mandatory" in err_msg

    # 4. Invalid payload structure (missing required field inside FirewallPayload)
    invalid_payload_event = {
        "event_id": "8c54324f-ef76-46b7-a3f1-4dbfa7f8841c",
        "event_type": "firewall",
        "source_system": "Perimeter Firewall",
        "timestamp": "2026-07-14T11:01:00Z",
        "severity": "INFO",
        "raw_payload": {
            "firewall_device_id": "FW_TEST_01",
            # missing source_ip, destination_ip, protocol, etc.
            "source_port": 49152,
            "destination_port": 443
        }
    }
    success, err_msg, _ = pipeline.ingest_event(invalid_payload_event)
    assert success is False
    assert "Payload validation failed" in err_msg

def test_timestamp_formatting():
    pipeline = IngestionPipeline()
    
    event = {
        "event_id": "8c54324f-ef76-46b7-a3f1-4dbfa7f8842a",
        "event_type": "firewall",
        "source_system": "Perimeter Firewall",
        "timestamp": "2026-07-14 11:00:00", # missing 'T' and 'Z'
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
    success, err_msg, _ = pipeline.ingest_event(event)
    assert success is False
    assert "ISO-8601 UTC format" in err_msg

    # Test invalid date values (e.g. Feb 30)
    event["timestamp"] = "2026-02-30T11:00:00Z"
    success, err_msg, _ = pipeline.ingest_event(event)
    assert success is False
    assert "invalid date" in err_msg

def test_duplicate_detection():
    pipeline = IngestionPipeline()
    
    event = {
        "event_id": "duplicate-uuid-1234",
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
    
    # Ingest first time (Success)
    success, _, _ = pipeline.ingest_event(event)
    assert success is True

    # Ingest second time (Failure - Duplicate)
    success, err_msg, _ = pipeline.ingest_event(event)
    assert success is False
    assert "Duplicate event rejected" in err_msg

def test_chronology_validation():
    pipeline = IngestionPipeline()
    
    base_event = {
        "event_type": "firewall",
        "source_system": "Perimeter Firewall",
        "severity": "INFO",
        "session_id": "SESS_CHRONO_99",
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
            "bytes_received": 1500,
            "session_id": "SESS_CHRONO_99"
        }
    }
    
    # Event 1: 11:00:00Z (Success)
    ev1 = base_event.copy()
    ev1["event_id"] = "uuid-chrono-01"
    ev1["timestamp"] = "2026-07-14T11:00:00Z"
    success, _, _ = pipeline.ingest_event(ev1)
    assert success is True

    # Event 2: 11:02:00Z (Success - Newer time)
    ev2 = base_event.copy()
    ev2["event_id"] = "uuid-chrono-02"
    ev2["timestamp"] = "2026-07-14T11:02:00Z"
    success, _, _ = pipeline.ingest_event(ev2)
    assert success is True

    # Event 3: 11:01:00Z (Failure - Out of order / Prior to last timestamp)
    ev3 = base_event.copy()
    ev3["event_id"] = "uuid-chrono-03"
    ev3["timestamp"] = "2026-07-14T11:01:00Z"
    success, err_msg, _ = pipeline.ingest_event(ev3)
    assert success is False
    assert "Chronology violation" in err_msg

def test_state_restoration():
    # Simulate writing historical log records manually to the file
    os.makedirs(os.path.dirname(TEST_OUTPUT_PATH), exist_ok=True)
    historical_events = [
        {
            "event_id": "hist-id-01",
            "event_type": "firewall",
            "source_system": "Perimeter Firewall",
            "timestamp": "2026-07-14T10:00:00Z",
            "severity": "INFO",
            "session_id": "SESS_HIST_01",
            "raw_payload": {}
        },
        {
            "event_id": "hist-id-02",
            "event_type": "firewall",
            "source_system": "Perimeter Firewall",
            "timestamp": "2026-07-14T10:05:00Z",
            "severity": "INFO",
            "session_id": "SESS_HIST_01",
            "raw_payload": {}
        }
    ]
    with open(TEST_OUTPUT_PATH, "w", encoding="utf-8") as f:
        for ev in historical_events:
            f.write(json.dumps(ev) + "\n")

    # Create fresh pipeline (restoring from history)
    pipeline = IngestionPipeline()
    pipeline.restore_state_if_needed()

    # Check 1: Duplicate check validates historical event ID
    dup_event = {
        "event_id": "hist-id-02",
        "event_type": "firewall",
        "source_system": "Perimeter Firewall",
        "timestamp": "2026-07-14T10:10:00Z",
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
    success, err_msg, _ = pipeline.ingest_event(dup_event)
    assert success is False
    assert "Duplicate event rejected" in err_msg

    # Check 2: Chronology check validates historical max timestamp (reloads max time 10:05:00Z)
    chrono_event = {
        "event_id": "hist-id-03",
        "event_type": "firewall",
        "source_system": "Perimeter Firewall",
        "timestamp": "2026-07-14T10:02:00Z", # older than 10:05:00Z
        "severity": "INFO",
        "session_id": "SESS_HIST_01",
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
            "bytes_received": 1500,
            "session_id": "SESS_HIST_01"
        }
    }
    success, err_msg, _ = pipeline.ingest_event(chrono_event)
    assert success is False
    assert "Chronology violation" in err_msg
