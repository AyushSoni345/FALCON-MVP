# FALCON Module Integration Guide

This guide explains how **Module 1 (Unified Data Ingestion Layer)** sends data into **Module 2 (Event Normalization & Threat Enrichment Layer)**, and how **Module 2** forwards the standardized output stream to **Module 3 (Security Context Graph)**.

---

## Architecture Flow

```mermaid
graph TD
    M1[Module 1: Unified Data Ingestion]
    M2[Module 2: Normalization & Enrichment]
    M3[Module 3: Security Context Graph]
    
    M1 -- Raw Event Stream (JSON) --> M2
    M2 -- REST /normalize/batch --> M2Engine[Normalization & Enrichment Engine]
    M2Engine -- Stateful Cache Checks --> Repo[Stateful Repository]
    M2Engine -- Context-Enriched Event --> M3
    M3 -- Node & Edge Construction --> Graph[(Security Knowledge Graph)]
```

---

## Sequence Diagram

The following sequence diagram outlines a single transaction event workflow from ingestion to knowledge graph edge construction:

```mermaid
sequenceDiagram
    autonumber
    participant M1 as Module 1 (Ingestion)
    participant M2 as Module 2 (Normalization & Enrichment)
    participant DB as M2 State Repository
    participant M3 as Module 3 (Context Graph)

    M1->>M2: POST /normalize {raw_event}
    Note over M2: Base Schema Mapping<br/>(Translate keys, normalize timestamp)
    M2->>DB: Fetch customer device & beneficiary history
    DB-->>M2: Return device list & last location
    Note over M2: Stateful Checks<br/>(Calculate velocity & impossible travel)
    M2->>M2: Threat Intel & MITRE ATT&CK Mapping
    M2->>DB: Save normalized event & update location/device state
    M2-->>M1: Return 200 OK with CommonOutputEvent
    M2->>M3: Push CommonOutputEvent (via message queue / event-broker)
    Note over M3: Parse customer_id, device_id, session_id, IP<br/>Construct graph nodes and link edges
```

---

## Integration Details

### Upstream (Module 1 -> Module 2)

Module 1 collects events and POSTs them to Module 2.

#### Example Integration Code (Python)
```python
import httpx
import asyncio

MODULE2_URL = "http://localhost:8000/normalize"

async def forward_event_to_module2(raw_event: dict):
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                MODULE2_URL,
                json={"event": raw_event},
                timeout=5.0
            )
            if response.status_code == 200:
                enriched_event = response.json()
                print(f"Normalized Event ID: {enriched_event['metadata']['event_id']}")
                return enriched_event
            else:
                print(f"Error from Module 2: {response.status_code} - {response.text}")
        except Exception as e:
            print(f"Failed to reach Module 2: {e}")
```

---

### Downstream (Module 2 -> Module 3)

The output of Module 2 is the **Context-Enriched Event Repository**. Every output event conform to the Pydantic-validated `CommonOutputEvent` structure.

To build the Security Knowledge Graph, Module 3 relies on the preserved identifiers. **Module 2 guarantees that these fields are never modified or altered.**

#### Critical Mapping Identifiers for Module 3
Module 3 maps these keys to build nodes and edges:
* **User/Employee**: `identity.username` and `identity.employee_id`
* **Customer**: `identity.customer_id`
* **Device**: `identity.device_id` / `device.device_id`
* **IP**: `identity.ip_address` / `network.source_ip`
* **Session**: `metadata.session_id` / `identity.session_id`
* **Transaction**: `transaction.transaction_id`
* **Account**: `identity.account_number` / `transaction.account_number`
* **Beneficiary**: `identity.beneficiary_id` / `transaction.beneficiary_id`
* **Endpoint**: `identity.endpoint_id`
* **Malware**: Detected file hashes under `raw_event.file_hash` matched by `threat` indicators.

---

## Merge Compatibility Checklist
* [x] **No Shared Library Conflicts**: Module 2 uses basic libraries (`FastAPI`, `Pydantic-Settings`, `Uvicorn`). It does not dictate database connectors for Modules 1 or 3.
* [x] **Zero Code Changes for Integration**: REST endpoints accept raw JSON dictionaries and output fully parsed schema-matching JSON structures. No custom classes need to be imported across module folders.
* [x] **Decoupled Data Store**: All local lookups and state checks are abstracted via the `StateRepository` interface in `app/database/repository.py`. The in-memory database configuration can be easily swapped with Redis/SQL without modifying the business logic.
