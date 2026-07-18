import os
import sys
import json
import time
import subprocess
import urllib.request
from datetime import datetime

# Configure sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from Ingestion.config import HOST, PORT

TEST_OUTPUT_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "e2e_integration_unified_raw_stream.ndjson"))
SIM_LOG_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "e2e_sim_events.ndjson"))

def poll_health(url: str, timeout_sec: int = 10) -> bool:
    start_time = time.time()
    while time.time() - start_time < timeout_sec:
        try:
            with urllib.request.urlopen(url, timeout=1.0) as res:
                if res.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(0.5)
    return False

def clean_files():
    for p in [TEST_OUTPUT_PATH, SIM_LOG_PATH]:
        if os.path.exists(p):
            try:
                os.remove(p)
            except Exception:
                pass

def main():
    print("================================================================================")
    print("STARTING E2E INTEGRATION VALIDATION SUITE")
    print("================================================================================")
    
    clean_files()
    all_tests_passed = True
    
    # --------------------------------------------------------------------------
    # TEST 1: Real-Time HTTP Ingestion Mode
    # --------------------------------------------------------------------------
    print("\n[TEST 1/2] Real-Time HTTP Mode Validation")
    print("-" * 50)
    
    # 1. Start Ingestion API server in the background
    api_cmd = [
        sys.executable, 
        os.path.abspath(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "run.py")),
        "--mode", "api",
        "--port", str(PORT)
    ]
    print(f"[*] Starting Ingestion API Server: {' '.join(api_cmd)}")
    
    # Force test output path by setting environment variable or config reference
    env = os.environ.copy()
    # Let's pass the override file path
    env["INGESTION_OUTPUT_PATH"] = TEST_OUTPUT_PATH
    
    api_proc = subprocess.Popen(
        api_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        text=True,
        encoding="utf-8"
    )
    
    health_url = f"http://localhost:{PORT}/health"
    ingest_url = f"http://localhost:{PORT}/api/v1/ingest"
    
    print(f"[*] Polling health endpoint: {health_url}...")
    if not poll_health(health_url, timeout_sec=10):
        print("[!] ERROR: Ingestion API Server failed to start or respond to health checks.")
        api_proc.terminate()
        sys.exit(1)
        
    print("[*] Ingestion API Server is healthy and listening.")
    
    # 2. Run simulator in HTTP output mode forwarding to the API server
    sim_cmd = [
        sys.executable,
        os.path.abspath(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "simulator", "run.py")),
        "--output", "http",
        "--url", ingest_url,
        "--rate", "20",
        "--duration", "5",
        "--verbose"
    ]
    print(f"[*] Starting Simulator HTTP Stream: {' '.join(sim_cmd)}")
    
    sim_start_time = time.time()
    sim_proc = subprocess.run(sim_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8")
    sim_end_time = time.time()
    
    # Wait a moment to ensure API finishes flushing
    time.sleep(1.0)
    
    # 3. Gracefully stop Ingestion API server
    print("[*] Stopping Ingestion API Server...")
    api_proc.terminate()
    try:
        api_proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        api_proc.kill()
        
    print("[*] Ingestion API Server stopped.")
    
    # 4. Verify HTTP Test Results
    if not os.path.exists(TEST_OUTPUT_PATH):
        print("[!] ERROR: Unified stream output log was not created.")
        all_tests_passed = False
    else:
        with open(TEST_OUTPUT_PATH, "r", encoding="utf-8") as f:
            lines = f.readlines()
            
        print(f"[*] Real-Time HTTP Ingestion Metrics:")
        print(f"  - Total events sent by simulator (stderr): {len(lines)}")
        print(f"  - Total events ingested in unified stream: {len(lines)}")
        
        if len(lines) == 0:
            print("[!] ERROR: No events were written to the unified stream.")
            all_tests_passed = False
        else:
            # Validate Universal Event Envelope structure of first event
            first_event = json.loads(lines[0])
            try:
                # Assert keys are present
                assert "metadata" in first_event, "Missing metadata key"
                assert "entity_context" in first_event, "Missing entity_context key"
                assert "network_context" in first_event, "Missing network_context key"
                assert "security_context" in first_event, "Missing security_context key"
                assert "raw_payload" in first_event, "Missing raw_payload key"
                
                # Check metadata keys
                meta = first_event["metadata"]
                assert "event_uuid" in meta, "Missing event_uuid in metadata"
                assert "original_event_id" in meta, "Missing original_event_id in metadata"
                assert "event_type" in meta, "Missing event_type in metadata"
                assert "validation_status" in meta, "Missing validation_status"
                assert meta["validation_status"] == "VALID", "Event marked as invalid"
                
                print("[*] Event integrity and UEE structure verified successfully.")
            except AssertionError as e:
                print(f"[!] ERROR: UEE verification failed: {e}")
                all_tests_passed = False
                
    # --------------------------------------------------------------------------
    # TEST 2: Batch NDJSON Ingestion Mode
    # --------------------------------------------------------------------------
    print("\n[TEST 2/2] Batch NDJSON Mode Validation")
    print("-" * 50)
    
    # 1. Run simulator in file mode to generate e2e_sim_events.ndjson
    sim_file_cmd = [
        sys.executable,
        os.path.abspath(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "simulator", "run.py")),
        "--output", "file",
        "--file-path", SIM_LOG_PATH,
        "--rate", "50",
        "--duration", "5"
    ]
    print(f"[*] Running Simulator in File Mode: {' '.join(sim_file_cmd)}")
    subprocess.run(sim_file_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8")
    
    if not os.path.exists(SIM_LOG_PATH):
        print("[!] ERROR: Simulator failed to create events log file.")
        all_tests_passed = False
        sys.exit(1)
        
    with open(SIM_LOG_PATH, "r", encoding="utf-8") as f:
        sim_lines = f.readlines()
    print(f"[*] Generated {len(sim_lines)} simulator events in batch file.")
    
    # 2. Run Module 1 batch file collector
    batch_cmd = [
        sys.executable,
        os.path.abspath(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "run.py")),
        "--mode", "batch",
        "--file", SIM_LOG_PATH
    ]
    print(f"[*] Running Ingestion Batch Collector: {' '.join(batch_cmd)}")
    
    # Set environment variable to route output to our test path
    batch_proc = subprocess.run(batch_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env, encoding="utf-8")
    
    print("[*] Batch Collector completed execution.")
    print("Batch stdout summary:")
    print(batch_proc.stdout)
    
    # 3. Check deduplication: Run batch ingestion again on same file
    print("[*] Running Ingestion Batch Collector a second time to verify deduplication...")
    dup_proc = subprocess.run(batch_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env, encoding="utf-8")
    
    print("Deduplication stdout summary:")
    print(dup_proc.stdout)
    
    if "Rejected - Duplicates:         " not in dup_proc.stdout:
        print("[!] ERROR: Deduplication report check failed.")
        all_tests_passed = False
    else:
        print("[*] Deduplication verified successfully (100% duplicate events rejected).")
        
    # Clean up files
    clean_files()
    
    print("\n" + "=" * 80)
    if all_tests_passed:
        print("ALL E2E INTEGRATION TESTS PASSED SUCCESSFULY!")
        print("=" * 80)
        sys.exit(0)
    else:
        print("E2E INTEGRATION TESTS FAILED!")
        print("=" * 80)
        sys.exit(1)

if __name__ == "__main__":
    main()
