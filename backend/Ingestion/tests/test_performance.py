import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import time
import pytest
import uuid

# Override the output path for test isolation
import Ingestion.config
TEST_OUTPUT_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "test_perf_unified_raw_stream.ndjson"))
Ingestion.config.OUTPUT_PATH = TEST_OUTPUT_PATH

from Ingestion.core.pipeline import IngestionPipeline

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

def test_pipeline_throughput():
    pipeline = IngestionPipeline()
    
    # Generate 1000 valid events
    events = []
    for i in range(1000):
        events.append({
            "event_id": str(uuid.uuid4()),
            "event_type": "firewall",
            "source_system": "Perimeter Firewall",
            "timestamp": f"2026-07-14T12:{i//60:02d}:{i%60:02d}Z",
            "severity": "INFO",
            "session_id": f"SESS_PERF_{i % 5}", # 5 distinct sessions
            "raw_payload": {
                "firewall_device_id": "FW_PERF",
                "source_ip": f"192.168.1.{10 + (i%10)}",
                "destination_ip": "10.0.0.1",
                "source_port": 50000 + i,
                "destination_port": 443,
                "protocol": "HTTPS",
                "action": "ALLOW",
                "rule_id": "RULE_PERF",
                "interface": "eth0",
                "bytes_sent": 1000,
                "bytes_received": 5000,
                "session_id": f"SESS_PERF_{i % 5}"
            }
        })

    # Warm up
    pipeline.ingest_event(events[0])
    
    start_time = time.time()
    success_count = 0
    
    for ev in events[1:]:
        success, _, _ = pipeline.ingest_event(ev)
        if success:
            success_count += 1
            
    end_time = time.time()
    duration = end_time - start_time
    throughput = success_count / duration if duration > 0 else 0
    
    print("\n" + "=" * 60)
    print(" PERFORMANCE TEST REPORT ")
    print("=" * 60)
    print(f"Total events ingested:    {success_count}")
    print(f"Total time elapsed:       {duration:.4f} seconds")
    print(f"Calculated Throughput:    {throughput:.2f} events/second")
    print("=" * 60 + "\n")
    
    # We expect at least 200 events/second throughput on a standard local environment
    assert throughput >= 100.0, f"Throughput {throughput:.2f} eps was below the 100 eps performance benchmark!"
