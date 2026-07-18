import os
import json
import sys
from collections import Counter

from Ingestion.core.pipeline import pipeline

class FileCollector:
    def __init__(self, source_path: str):
        self.source_path = os.path.abspath(source_path)

    def process(self) -> dict:
        """
        Processes events from the source NDJSON file line-by-line.
        Appends valid events to the unified stream.
        """
        print(f"[*] Starting batch file ingestion from: {self.source_path}")
        
        if not os.path.exists(self.source_path):
            print(f"[!] Error: Source file not found: {self.source_path}", file=sys.stderr)
            return {"status": "error", "error": "Source file not found"}

        metrics = {
            "total_lines": 0,
            "ingested": 0,
            "rejected_invalid_json": 0,
            "rejected_schema": 0,
            "rejected_duplicate": 0,
            "rejected_chronology": 0,
            "other_errors": 0
        }

        # Track event type distributions of ingested events
        ingested_types = Counter()

        with open(self.source_path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                
                metrics["total_lines"] += 1

                # 1. Check valid JSON
                try:
                    event_dict = json.loads(line)
                except Exception as e:
                    metrics["rejected_invalid_json"] += 1
                    print(f"  [Line {line_num}]: Invalid JSON format: {e}")
                    continue

                # 2. Ingest through pipeline
                success, err_msg, success_payload = pipeline.ingest_event(event_dict)
                
                if success:
                    metrics["ingested"] += 1
                    etype = event_dict.get("event_type", "unknown")
                    ingested_types[etype] += 1
                else:
                    # Categorize rejection error
                    if "Envelope validation" in err_msg or "Payload validation" in err_msg or "mandatory" in err_msg or "Timestamp" in err_msg or "Unknown event_type" in err_msg:
                        metrics["rejected_schema"] += 1
                    elif "Duplicate event" in err_msg:
                        metrics["rejected_duplicate"] += 1
                    elif "Chronology violation" in err_msg:
                        metrics["rejected_chronology"] += 1
                    else:
                        metrics["other_errors"] += 1
                    
                    print(f"  [Line {line_num}]: Rejected event (ID: {event_dict.get('event_id', 'N/A')}): {err_msg}")

        # Ingestion metrics report
        print("\n" + "=" * 60)
        print(" BATCH INGESTION SUMMARY REPORT ")
        print("=" * 60)
        print(f"Total lines processed:         {metrics['total_lines']}")
        print(f"Events Ingested successfully:  {metrics['ingested']}")
        print(f"Rejected - Invalid JSON:       {metrics['rejected_invalid_json']}")
        print(f"Rejected - Schema/Mandatory:   {metrics['rejected_schema']}")
        print(f"Rejected - Duplicates:         {metrics['rejected_duplicate']}")
        print(f"Rejected - Chronology:         {metrics['rejected_chronology']}")
        print(f"Rejected - Other errors:       {metrics['other_errors']}")
        
        if metrics["ingested"] > 0:
            print("\n Ingested Event Types Distribution:")
            for etype, count in ingested_types.most_common():
                pct = (count / metrics["ingested"]) * 100
                print(f"  - {etype.upper():<20} : {count:<5} ({pct:.2f}%)")
        print("=" * 60 + "\n")

        return {
            "status": "success",
            "metrics": metrics
        }
