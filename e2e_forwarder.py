import os
import time
import json
import requests
from dotenv import load_dotenv

# Load env variables for ports
load_dotenv()

PORTS = {
    "ingest": os.environ.get("INGESTION_PORT", 8001),
    "normalize": os.environ.get("NORMALIZATION_PORT", 8002),
    "graph": os.environ.get("GRAPH_PORT", 8003),
    "correlate": os.environ.get("CORRELATION_PORT", 8004),
    "analytics": os.environ.get("ANALYTICS_PORT", 8005),
    "risk": os.environ.get("RISK_PORT", 8006),
    "explain": os.environ.get("EXPLAINABILITY_PORT", 8007),
    "response": os.environ.get("RESPONSE_PORT", 8008),
}

ENDPOINTS = {
    "normalize": f"http://127.0.0.1:{PORTS['normalize']}/normalize",
    "graph": f"http://127.0.0.1:{PORTS['graph']}/events",
    "correlate": f"http://127.0.0.1:{PORTS['correlate']}/api/v1/correlate",
    "analyze": f"http://127.0.0.1:{PORTS['analytics']}/module5/analyze",
    "evaluate": f"http://127.0.0.1:{PORTS['risk']}/evaluate",
    "explain": f"http://127.0.0.1:{PORTS['explain']}/api/v1/explain",
    "process": f"http://127.0.0.1:{PORTS['response']}/process",
}

def tail_file(file_path):
    # Move to the end of file initially, or read from start if we want to process everything?
    # To demonstrate MVP, let's process from start but track processed lines.
    processed_lines = set()
    while True:
        if os.path.exists(file_path):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    for i, line in enumerate(f):
                        if i not in processed_lines:
                            line = line.strip()
                            if line:
                                yield i, json.loads(line)
                            processed_lines.add(i)
            except Exception as e:
                print(f"[Forwarder] Error reading file: {e}")
        time.sleep(1)

def forward_event(uee):
    event_id = uee.get("metadata", {}).get("original_event_id", "UNKNOWN")
    print(f"\n[Forwarder] Pipeline starting for event: {event_id}")
    
    try:
        # Step 2: Normalize (UEE -> CEE)
        print(f"  -> Sending to Module 2 (Normalize)...")
        res2 = requests.post(ENDPOINTS["normalize"], json=uee)
        if res2.status_code != 200:
            print(f"  [X] Module 2 failed: {res2.status_code} - {res2.text[:200]}")
            return
        cee = res2.json()

        # Step 3: Graph (CEE -> GraphEvent)
        print(f"  -> Sending to Module 3 (Graph)...")
        res3 = requests.post(ENDPOINTS["graph"], json=cee)
        if res3.status_code != 200:
            print(f"  [X] Module 3 failed: {res3.status_code} - {res3.text[:200]}")
            return
        graph_event = res3.json()

        # Step 4: Correlate (GraphEvent -> Incident)
        print(f"  -> Sending to Module 4 (Correlate)...")
        res4 = requests.post(ENDPOINTS["correlate"], json=graph_event)
        if res4.status_code != 200 and res4.status_code != 201:
            print(f"  [X] Module 4 failed: {res4.status_code} - {res4.text[:200]}")
            return
        incident = res4.json()

        # Check if Correlation engine detected anything
        confidence = incident.get("confidence_assessment", {}).get("overall_confidence", 0)
        if confidence < 0.2:
            print(f"  -> [End] Event {event_id} has low confidence ({confidence}). Stopping pipeline.")
            return

        # Step 5: Analytics (Incident -> DomainAIAssessment)
        print(f"  -> Sending to Module 5 (Analyze)...")
        res5 = requests.post(ENDPOINTS["analyze"], json=incident)
        if res5.status_code != 200:
            print(f"  [X] Module 5 failed: {res5.status_code} - {res5.text[:200]}")
            return
        assessment = res5.json()

        # Step 6: Risk (DomainAIAssessment -> UnifiedRiskAssessment)
        print(f"  -> Sending to Module 6 (Evaluate)...")
        res6 = requests.post(ENDPOINTS["evaluate"], json=assessment)
        if res6.status_code != 200:
            print(f"  [X] Module 6 failed: {res6.status_code} - {res6.text[:200]}")
            return
        unified_risk = res6.json()

        # Step 7: Explain (UnifiedRiskAssessment -> ExplainableThreatReport)
        print(f"  -> Sending to Module 7 (Explain)...")
        res7 = requests.post(ENDPOINTS["explain"], json=unified_risk)
        if res7.status_code != 200:
            print(f"  [X] Module 7 failed: {res7.status_code} - {res7.text[:200]}")
            return
        threat_report = res7.json()

        # Step 8: Process (ExplainableThreatReport -> IRLP)
        print(f"  -> Sending to Module 8 (Process Response)...")
        res8 = requests.post(ENDPOINTS["process"], json=threat_report)
        if res8.status_code != 200:
            print(f"  [X] Module 8 failed: {res8.status_code} - {res8.text[:200]}")
            return
        
        print(f"  [✓] Pipeline COMPLETE for event {event_id}")

    except Exception as e:
        print(f"  [X] Pipeline error: {e}")

def main():
    ndjson_path = os.path.join("backend", "Ingestion", "output", "unified_raw_stream.ndjson")
    print(f"[Forwarder] Monitoring {ndjson_path} for new events...")
    for idx, event in tail_file(ndjson_path):
        forward_event(event)

if __name__ == "__main__":
    main()
