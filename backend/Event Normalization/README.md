# FALCON Module 2: Event Normalization & Threat Enrichment Layer

FALCON Module 2 is a production-ready, asynchronous Python FastAPI microservice responsible for normalizing and enriching incoming security logs and banking transactions from Module 1 (Unified Data Ingestion Layer) before they are sent to Module 3 (Security Context Graph).

---

## Key Features

1. **Schema Standardization**: Converts raw logs of diverse types (Firewall, EDR/XDR, VPN, IAM, UPI, Card, ATM, etc.) into a single, unified Pydantic-validated output schema.
2. **Identity Resolution**: Tracks session and credential mappings (e.g., SessionID -> CustomerID, IP -> Username) in memory to resolve identity linkages dynamically.
3. **Asset & Zone Contextualization**: Attaches network zone classifications (DMZ, Internal, Branch, External) and device categories based on telemetry origin.
4. **Local Geolocation Registry**: Converts public IP sources into coordinates, ASNs, ISPs, and risk scores deterministically using local dictionaries without incurring external API overhead.
5. **Local Threat Intelligence Service**: Matches IOCs, malicious IPs, phishing domains, and file hashes against high-performance local dictionaries (easily swappable for real DB feeds).
6. **MITRE ATT&CK Mapping**: Maps security alerts and transaction anomalies directly to MITRE Tactics (e.g., Credential Access, Exfiltration, Initial Access) and Technique IDs (e.g., T1110, T1048, T1133).
7. **Stateful Behavioral Fraud Engine**: Evaluates complex transaction anomalies in real-time:
   * **Impossible Travel**: Computes physical travel velocity between subsequent user transactions/logins using the Haversine distance formula.
   * **Dormant Account Alert**: Triggers if an account initiates a transaction after more than 90 days of inactivity.
   * **Rapid Transaction Indicator**: Identifies velocity spikes (multiple transactions within 5 seconds).
   * **New Device/Beneficiary**: Alerts on unrecognized hardware footprints or newly registered beneficiaries.
   * **Geo Mismatch**: Evaluates transaction card/ATM country codes against IP geolocation telemetry.

---

## Project Structure

```text
c:\FALCON/
├── Dockerfile                  # Containerization instructions
├── docker-compose.yml          # Container orchestration (port 8000)
├── requirements.txt            # Package dependencies
├── README.md                   # Setup and development guide
├── app/
│   ├── main.py                 # FastAPI application entrypoint
│   ├── config.py               # Pydantic environment configuration
│   ├── logging_config.py       # Custom structured JSON logger
│   ├── dependencies.py         # Dependency injection providers
│   ├── api/
│   │   ├── models.py           # API request/response validation schemas
│   │   └── routes.py           # Route endpoints (/normalize, /metrics, etc.)
│   ├── core/
│   │   ├── engine.py           # Pipeline orchestrator
│   │   ├── schema.py           # Common Output Schema model definitions
│   │   ├── normalizers.py      # Telemetry translation logic
│   │   ├── resolver.py         # Identity correlation registry
│   │   └── enrichment/
│   │       ├── base.py         # Enricher interface
│   │       ├── geo.py          # Geolocation lookup service
│   │       ├── threat_intel.py # Threat intelligence feed checker
│   │       ├── mitre.py        # MITRE ATT&CK framework mapping
│   │       └── fraud.py        # Stateful transaction fraud checks
│   └── database/
│       ├── repository.py       # Repository interface
│       └── memory_repo.py      # In-memory database repository
├── docs/
│   ├── API.md                  # REST endpoint definitions
│   ├── integration_guide.md    # Guide for Module 1 & Module 3 teams
│   └── solution_architecture.md# Master platform design context
└── tests/                      # Automated test suite
    ├── conftest.py
    ├── test_api.py
    ├── test_normalizers.py
    └── test_enrichment.py
```

---

## Installation & Setup

### Prerequisites
* Python 3.10 or higher
* Docker & Docker Compose (optional)

### Local Virtual Environment Setup
1. Clone the repository and navigate to the project directory:
   ```bash
   cd c:\FALCON
   ```
2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   # On Windows:
   .\venv\Scripts\activate
   # On macOS/Linux:
   source venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Run the FastAPI development server:
   ```bash
   uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
   ```
5. View the interactive OpenAPI documentation at [http://localhost:8000/docs](http://localhost:8000/docs).

---

## Running with Docker

You can build and spin up the service in a single command using docker-compose:
```bash
docker-compose up --build -d
```
The server will start on port `8000`. You can verify container status:
```bash
docker-compose ps
```

---

## Testing

The project includes a robust test suite covering normalizers, enrichers, identity resolution, stateful fraud indicators, and API endpoints.

To run the tests, execute `pytest` in your terminal:
```bash
pytest -v
```
To run tests with code coverage:
```bash
pip install pytest-cov
pytest --cov=app tests/
```

---

## API Summary

* **`POST /normalize`**: Accept a single raw event and return a standardized, enriched common output schema event.
* **`POST /normalize/batch`**: Accept a list of raw events and return a list of standardized, enriched common output schema events.
* **`GET /health`**: Returns API status, environment mode, and server version.
* **`GET /schema`**: Returns metadata and summaries of fields in the FALCON Common Output Schema.
* **`GET /metrics`**: Returns metrics including total events processed, active sessions tracked, and threat alerts triggered.
