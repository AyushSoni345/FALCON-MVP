# FALCON Module 2: REST API Documentation

This document describes the request models, response models, query structures, and example payloads for the Event Normalization & Threat Enrichment Layer (Module 2).

---

## 1. POST /normalize

Accepts a Module 1 Universal Event Envelope, runs specialized parsing, resolves identity and assets, and applies full geographic, threat, MITRE, and behavioral fraud context enrichments.

* **URL**: `/normalize`
* **Method**: `POST`
* **Headers**: `Content-Type: application/json`

### Request Body (UniversalEventEnvelope)

The request payload must contain exactly the following structure:

```json
{
  "metadata": {
    "event_uuid": "e1a90c12-32b4-4b5c-a67e-1289cf012345",
    "original_event_id": "fw-log-90812",
    "event_type": "FIREWALL",
    "event_category": "network",
    "source_system": "PaloAlto-FW-01",
    "source_vendor": "Palo Alto Networks",
    "ingestion_timestamp": "2026-07-14T11:15:29Z",
    "original_timestamp": "2026-07-14T11:15:28Z",
    "processing_timestamp": "2026-07-14T11:15:30Z",
    "validation_status": "VALID",
    "duplicate_status": "UNIQUE",
    "schema_version": "1.0",
    "event_hash": "a4f89d023b1287eac901b223cde897f1",
    "correlation_id": "c0a2103f-9812-4210-b982-f091c8901234",
    "pipeline_version": "1.0.0",
    "processing_status": "PENDING"
  },
  "entity_context": {
    "device_id": "dev-corp-laptop-102",
    "session_id": "sess-corp-9912"
  },
  "network_context": {
    "source_ip": "192.168.1.45",
    "destination_ip": "185.220.101.5",
    "source_port": 54129,
    "destination_port": 443,
    "protocol": "TCP"
  },
  "security_context": {
    "severity": "HIGH",
    "action": "BLOCK",
    "rule_id": "deny-malicious-outbound",
    "sensor_id": "sensor-palo-hq",
    "log_source": "Firewall"
  },
  "raw_payload": {
    "SRC_IP": "192.168.1.45",
    "DST_IP": "185.220.101.5",
    "SOURCE_PORT": "54129",
    "DESTINATION_PORT": "443",
    "PROTOCOL": "TCP",
    "ACTION": "BLOCK",
    "RULE_ID": "deny-malicious-outbound",
    "BYTES_SENT": "1500",
    "BYTES_RECEIVED": "0"
  }
}
```

### Response Body (ContextEnrichedEvent)

A success response (`200 OK`) returns exactly the 12 top-level sections of the Context Enriched Event:

```json
{
  "event_information": {
    "event_uuid": "e1a90c12-32b4-4b5c-a67e-1289cf012345",
    "original_event_id": "fw-log-90812",
    "event_type": "FIREWALL",
    "event_category": "network",
    "source_system": "PaloAlto-FW-01",
    "source_vendor": "Palo Alto Networks",
    "normalized_timestamp": "2026-07-14T11:15:30Z",
    "original_timestamp": "2026-07-14T11:15:28Z",
    "ingestion_timestamp": "2026-07-14T11:15:29Z",
    "processing_timestamp": "2026-07-14T11:15:30Z",
    "correlation_id": "c0a2103f-9812-4210-b982-f091c8901234",
    "batch_id": null,
    "stream_id": null,
    "schema_version": "1.0",
    "pipeline_version": "1.0.0",
    "processing_status": "SUCCESS",
    "processing_duration_ms": 2.45
  },
  "identity_context": {
    "customer_id": null,
    "employee_id": null,
    "user_id": null,
    "username": null,
    "account_number": null,
    "card_number_masked": null,
    "customer_type": null,
    "role": null,
    "department": null,
    "authentication_method": null,
    "authentication_status": null,
    "mfa_status": null
  },
  "asset_context": {
    "device_id": "dev-corp-laptop-102",
    "endpoint_id": null,
    "device_type": "Firewall",
    "operating_system": null,
    "browser": null,
    "firewall": "deny-malicious-outbound",
    "vpn_gateway": null,
    "atm_id": null,
    "pos_terminal": null,
    "server_id": null,
    "asset_name": null,
    "asset_group": null,
    "asset_location": null,
    "asset_owner": null,
    "asset_criticality": null
  },
  "network_context": {
    "source_ip": "192.168.1.45",
    "destination_ip": "185.220.101.5",
    "public_ip": "185.220.101.5",
    "source_port": 54129,
    "destination_port": 443,
    "protocol": "TCP",
    "country": "Germany",
    "city": "Berlin",
    "region": "Berlin",
    "network_zone": "Internal",
    "vpn_used": false,
    "proxy_used": false,
    "asn": "AS20473",
    "isp": "Tor Server Provider",
    "connection_type": null
  },
  "financial_context": {
    "transaction_id": null,
    "transaction_type": null,
    "payment_channel": null,
    "amount": null,
    "currency": null,
    "sender_account": null,
    "receiver_account": null,
    "beneficiary_id": null,
    "receiver_bank": null,
    "merchant": null,
    "merchant_category": null,
    "branch": null,
    "transaction_status": null,
    "account_balance": null,
    "approval_code": null,
    "ifsc": null
  },
  "security_context": {
    "severity": "HIGH",
    "action": "BLOCK",
    "attack_name": null,
    "signature": null,
    "signature_id": null,
    "rule_name": null,
    "rule_id": "deny-malicious-outbound",
    "sensor_id": "sensor-palo-hq",
    "log_source": "Firewall",
    "malware_name": null,
    "process_name": null,
    "process_hash": null,
    "detection_status": null,
    "encryption_status": null,
    "cpu_usage": null,
    "memory_usage": null
  },
  "threat_context": {
    "IOC_match": true,
    "IOC_value": "185.220.101.5",
    "IOC_type": "IP_ADDRESS",
    "IOC_confidence": 0.85,
    "malicious_ip": "185.220.101.5",
    "malicious_domain": null,
    "malicious_hash": null,
    "threat_actor": "APT28",
    "malware_family": null,
    "ATTACK_campaign": "Operation Cobalt",
    "MITRE_tactic": "Initial Access",
    "MITRE_technique": "External Remote Services",
    "MITRE_technique_id": "T1133",
    "C2_server": null,
    "reputation_score": 8.5,
    "intel_source": "FALCON_Threat_Intel_Feeds",
    "intel_timestamp": "2026-07-14T11:15:30Z"
  },
  "fraud_context": {
    "high_risk_beneficiary": false,
    "mule_account": false,
    "blacklisted_account": false,
    "high_risk_country": false,
    "risky_merchant": false,
    "first_time_payee": false,
    "rapid_beneficiary_addition": false,
    "unusual_transaction_pattern": false,
    "velocity_indicator": 0.0,
    "large_transfer": false,
    "new_payee": false,
    "new_merchant": false
  },
  "geo_context": {
    "country": "Germany",
    "city": "Berlin",
    "region": "Berlin",
    "latitude": 52.52,
    "longitude": 13.405,
    "timezone": "UTC",
    "asn": "AS20473",
    "isp": "Tor Server Provider",
    "geo_source": "IP_Database",
    "lookup_timestamp": "2026-07-14T11:15:30Z"
  },
  "behavioral_features": {
    "new_device": false,
    "new_location": false,
    "first_login_today": false,
    "unusual_login_hour": false,
    "multiple_failed_logins": false,
    "high_transaction_amount": false,
    "repeated_transactions": false,
    "foreign_transaction": false,
    "multiple_atm_usage": false,
    "new_browser": false,
    "new_operating_system": false,
    "abnormal_cpu_usage": false,
    "abnormal_memory_usage": false,
    "large_archive_access": false,
    "bulk_encrypted_transfer": false,
    "possible_impossible_travel": false,
    "new_beneficiary": false,
    "new_ip": false,
    "new_network": false
  },
  "relationship_context": {
    "customer_id": null,
    "employee_id": null,
    "session_id": "sess-corp-9912",
    "device_id": "dev-corp-laptop-102",
    "endpoint_id": null,
    "beneficiary_id": null,
    "transaction_id": null,
    "parent_event": null,
    "linked_events": [],
    "relationship_keys": {
      "device_session": "dev-corp-laptop-102:::sess-corp-9912"
    },
    "identity_chain": [
      "ip:192.168.1.45"
    ],
    "asset_chain": [
      "device:dev-corp-laptop-102"
    ],
    "transaction_chain": []
  },
  "normalized_event_data": {
    "source_ip": "192.168.1.45",
    "destination_ip": "185.220.101.5",
    "source_port": 54129,
    "destination_port": 443,
    "protocol": "TCP",
    "action": "BLOCK",
    "rule_id": "deny-malicious-outbound",
    "bytes_sent": 1500,
    "bytes_received": 0
  }
}
```

---

## 2. POST /normalize/batch

Processes multiple envelopes sequentially, returning an array of results. If one or more envelopes contain errors, the endpoint returns an `HTTP 207 Multi-Status` code with mixed success models and error objects.

* **URL**: `/normalize/batch`
* **Method**: `POST`
* **Headers**: `Content-Type: application/json`

---

## 3. GET /health

Returns service health status.

* **URL**: `/health`
* **Method**: `GET`
* **Response Status**: `200 OK`
* **Response Body**:
  ```json
  {
    "status": "healthy",
    "environment": "development",
    "version": "2.0.0"
  }
  ```

---

## 4. GET /schema

Describes canonical metadata fields.

* **URL**: `/schema`
* **Method**: `GET`
* **Response Status**: `200 OK`

---

## 5. GET /metrics

Exposes processing analytics.

* **URL**: `/metrics`
* **Method**: `GET`
* **Response Status**: `200 OK`
