import os
import sys
import argparse
import uvicorn

# Add current Ingestion base folder to sys.path so imports work properly
# when executed as python Ingestion/run.py
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Ingestion.config import HOST, PORT
from Ingestion.collectors.file_collector import FileCollector

def main():
    parser = argparse.ArgumentParser(
        description="FinGuard AI Unified Ingestion Layer - Module 1 CLI Runner"
    )
    parser.add_argument(
        "-m", "--mode",
        choices=["api", "batch"],
        required=True,
        help="Execution mode: api (HTTP REST API) or batch (NDJSON file reader)"
    )
    parser.add_argument(
        "-f", "--file",
        default="",
        help="Path to simulator NDJSON log file (required for batch mode)"
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=PORT,
        help=f"FastAPI server listening port (default: {PORT})"
    )

    args = parser.parse_args()

    if args.mode == "api":
        print("=" * 60)
        print(" Starting Unified Ingestion REST API Server ")
        print("=" * 60)
        # Run FastAPI app via uvicorn
        uvicorn.run("Ingestion.api.ingest:app", host=HOST, port=args.port, reload=False)

    elif args.mode == "batch":
        if not args.file:
            print("Error: You must provide a source file path using -f / --file in batch mode.", file=sys.stderr)
            sys.exit(1)
            
        collector = FileCollector(args.file)
        result = collector.process()
        
        if result["status"] == "error":
            sys.exit(1)
        else:
            sys.exit(0)

if __name__ == "__main__":
    main()
