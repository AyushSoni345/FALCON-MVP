import os

HOST = "0.0.0.0"
PORT = int(os.environ.get("INGESTION_PORT", 8001))

# Base directory for the Ingestion module
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Target NDJSON file path for the unified ingestion stream
OUTPUT_PATH = os.environ.get("INGESTION_OUTPUT_PATH", os.path.abspath(os.path.join(BASE_DIR, "output", "unified_raw_stream.ndjson")))

# Max seen event IDs to hold in the in-memory cache to prevent leaks
MAX_SEEN_CACHE = 100000
