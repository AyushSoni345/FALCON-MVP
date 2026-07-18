# FinGuard AI: Event Simulation Layer

The Event Simulation Layer is a banking-grade synthetic log generator designed to emulate the digital ecosystem of a modern bank. It produces high-fidelity, correlated, and chronologically consistent log events across cybersecurity telemetry and transactional systems.

This layer serves as the primary data generation engine for the **FinGuard AI** prototype, enabling realistic testing of ingestion pipelines, feature store updates, real-time correlation models, fraud engines, and Security Operations Center (SOC) dashboards.

---

## 🚀 Key Features

- **15 Integrated Data Sources**: Emulates diverse systems inside a bank:
  - *Network:* Perimeter & Corporate Firewall, Intrusion Detection Systems (IDS/IPS), VPN Gateway
  - *Identity:* Active Directory Authentication, Local ATM Auth, Internet Banking Logins
  - *Transactions:* Core Banking, UPI Node Manager, Payment Processors (NEFT/RTGS/IMPS), Card Merchant Networks, ATM Switches
  - *Endpoints:* EDR/XDR Sensor Agents running on workstations and ATMs
  - *Alerting & Intel:* SIEM alert triggers, Threat Intelligence Indicators of Compromise (IOCs)
  - *Specialized System:* Quantum/HNDL Archive access audit logs
- **Coordinated Attack Library**: Injects 7 complex, multi-stage attack scenarios including:
  1. *Credential Theft:* Internal LSASS memory dump, followed by remote Tor login, MFA bypass, beneficiary addition, and high-value transfer.
  2. *Malware & Exfiltration:* PDF execution, EDR alert, C2 beaconing, Quantum archive access, and database exfiltration to a blacklisted IP.
  3. *Brute Force & Privilege Escalation:* Repeated login failures, firewall blocks, IDS alerts, successful login, and Windows local group modifications.
  4. *Insider Threat (HNDL):* DBA VPN login at anomalous hours, customer records queries, Quantum archive reads, and legacy SSL large file transfers.
  5. *Account Takeover:* Impossible travel (Mumbai login then Germany login 5 mins later), beneficiary creation, NEFT transaction, and card POS declines.
  6. *Card Fraud:* High-velocity multiple country transactions and repeated POS/online declines.
  7. *ATM Jackpotting:* Local maintenance technician login, PLOUTUS malware EDR execution alert, and out-of-band large cash-out withdrawals.
- **Deep Correlation Matrix**: Automatically link events across channels by reusing `Session ID`, `Customer ID`, `Employee ID`, `Device ID`, `IP Address`, and `Correlation ID`.
- **Multiple Output Modes**:
  - `file`: Exports events continuously to a local NDJSON log file (perfect for file-tailing collectors).
  - `stdout`: Streams JSON records directly to standard output (allowing command-line piping).
  - `http`: Forwards events in real-time via HTTP POST to a target ingestion API.

---

## 🛠️ Folder Structure

```
simulator/
├── config.py             # Global thread-safe configuration and simulation states
├── models.py             # Pydantic V2 schemas validating 15 log types and envelope
├── data_generator.py     # Entity database pools (1,000 customers, 100 employees, ATMs, IOCs)
├── scenarios.py          # Setup scripts for normal activities and 7 attack chains
├── engine.py             # Event loop scheduler, log exporter, and background runner
├── run.py                # Command-line runner CLI interface
└── requirements.txt      # Dependency specification
```

---

## ⚙️ Installation & Setup

1. **Verify Prerequisites**: Ensure Python 3.9+ is installed.
2. **Install Dependencies**:
   ```bash
   pip install -r simulator/requirements.txt
   ```
3. **Run the Simulator**:
   * Output continuously to file (default):
     ```bash
     python simulator/run.py --output file --file-path simulator/events.ndjson --rate 2.0 --verbose
     ```
   * Stream JSON events directly to stdout (for pipeline ingestion):
     ```bash
     python simulator/run.py --output stdout
     ```
   * Trigger a single scenario (e.g. `attack_ato`) and exit:
     ```bash
     python simulator/run.py --trigger attack_ato --output stdout
     ```
   * Send events directly to an API endpoint via HTTP POST:
     ```bash
     python simulator/run.py --output http --url http://localhost:8000/api/v1/ingest --rate 5.0 --verbose
     ```

---

## 📊 Event Outputs

The simulation engine automatically exports generated logs in real-time to a local file in **New-line Delimited JSON (NDJSON)** format:
- **Default Path**: `simulator/events.ndjson`
- **Envelope Schema**: Every log is wrapped in a standard ingest envelope to simplify downstream parsing:
  ```json
  {
    "event_id": "UUID-String",
    "event_type": "firewall | iam | upi | core_banking | endpoint ...",
    "source_system": "System name",
    "timestamp": "UTC ISO-8601 Timestamp",
    "severity": "INFO | LOW | MEDIUM | HIGH | CRITICAL",
    "correlation_id": "Link identifier or null",
    "customer_id": "Customer UUID or null",
    "employee_id": "Employee UUID or null",
    "device_id": "Device UUID or null",
    "session_id": "Session UUID or null",
    "ip_address": "IP String or null",
    "raw_payload": { ... } // Source-specific payload dictionary
  }
  ```
