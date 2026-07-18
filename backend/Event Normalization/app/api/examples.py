from typing import Dict, Any

# Helper to generate basic base CEE template for responses
def _base_response(req_val: Dict[str, Any], normalized_event_data: Dict[str, Any], **kwargs) -> Dict[str, Any]:
    meta = req_val["metadata"]
    
    # 1. Resolve source IP
    source_ip = req_val["network_context"].get("source_ip")
    dest_ip = req_val["network_context"].get("destination_ip")
    
    # 2. Determine default Geo Context (reflect private vs public)
    def is_private(ip):
        if not ip:
            return True
        parts = ip.split(".")
        if len(parts) != 4:
            return True
        # 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        if parts[0] == "127" or parts[0] == "10":
            return True
        if parts[0] == "192" and parts[1] == "168":
            return True
        if parts[0] == "172" and (16 <= int(parts[1]) <= 31):
            return True
        return False

    is_gps = kwargs.get("is_gps", False)
    
    if is_gps:
        geo = {
            "country": kwargs.get("country", "India"),
            "city": kwargs.get("city", "Bengaluru"),
            "region": kwargs.get("region", "Karnataka"),
            "latitude": kwargs.get("latitude", 12.9716),
            "longitude": kwargs.get("longitude", 77.5946),
            "timezone": "Asia/Kolkata",
            "asn": "N/A",
            "isp": "N/A",
            "geo_source": "GPS",
            "lookup_timestamp": "2026-07-14T11:15:30Z"
        }
    elif is_private(source_ip):
        geo = {
            "country": "Internal Network",
            "city": "Private subnet",
            "region": "Local",
            "latitude": 0.0,
            "longitude": 0.0,
            "timezone": "UTC",
            "asn": "N/A",
            "isp": "Internal Routing",
            "geo_source": "PrivateIP",
            "lookup_timestamp": "2026-07-14T11:15:30Z"
        }
    else:
        # Static mappings for mock public IPs
        db = {
            "185.220.101.5": {
                "country": "Germany", "region": "Berlin", "city": "Berlin",
                "latitude": 52.5200, "longitude": 13.4050, "asn": "AS20473", "isp": "Tor Server Provider"
            },
            "45.9.148.15": {
                "country": "Russia", "region": "Moscow", "city": "Moscow",
                "latitude": 55.7558, "longitude": 37.6173, "asn": "AS60924", "isp": "ShadowNet Hosting"
            },
            "8.8.8.8": {
                "country": "United States", "region": "California", "city": "Mountain View",
                "latitude": 37.4220, "longitude": -122.0841, "asn": "AS15169", "isp": "Google LLC"
            },
            "106.51.78.23": {
                "country": "India", "region": "Karnataka", "city": "Bengaluru",
                "latitude": 12.9716, "longitude": 77.5946, "asn": "AS9829", "isp": "BSNL"
            }
        }
        info_geo = db.get(source_ip, {
            "country": "United States", "region": "New York", "city": "New York",
            "latitude": 40.7128, "longitude": -74.0060, "asn": "AS701", "isp": "Verizon"
        })
        geo = {
            "country": info_geo["country"],
            "city": info_geo["city"],
            "region": info_geo["region"],
            "latitude": info_geo["latitude"],
            "longitude": info_geo["longitude"],
            "timezone": "UTC",
            "asn": info_geo["asn"],
            "isp": info_geo["isp"],
            "geo_source": "IP_Database",
            "lookup_timestamp": "2026-07-14T11:15:30Z"
        }

    # 3. Determine Threat Context (reflect static DB mappings)
    # Check source_ip first, then dest_ip
    threat = {
        "IOC_match": False,
        "IOC_value": None,
        "IOC_type": None,
        "IOC_confidence": 0.0,
        "malicious_ip": None,
        "malicious_domain": None,
        "malicious_hash": None,
        "threat_actor": None,
        "malware_family": None,
        "ATTACK_campaign": None,
        "MITRE_tactic": kwargs.get("mitre_tactic"),
        "MITRE_technique": kwargs.get("mitre_technique"),
        "MITRE_technique_id": kwargs.get("mitre_technique_id"),
        "C2_server": None,
        "reputation_score": 0.0,
        "intel_source": "FALCON_Threat_Intel_Feeds",
        "intel_timestamp": "2026-07-14T11:15:30Z"
    }

    raw_payload = req_val.get("raw_payload", {})
    sec_ctx = req_val.get("security_context", {})
    file_hash = sec_ctx.get("process_hash") or raw_payload.get("Process_Hash")

    if source_ip in ["185.220.101.5", "45.9.148.15"]:
        ip_db = {
            "185.220.101.5": {"actor": "APT28", "campaign": "Operation Cobalt", "reason": "Tor Exit Node"},
            "45.9.148.15": {"actor": "Wizard Spider", "campaign": "Ryuk Ransomware", "reason": "C2 callback"}
        }
        threat.update({
            "IOC_match": True,
            "IOC_value": source_ip,
            "IOC_type": "IP_ADDRESS",
            "IOC_confidence": 0.95,
            "malicious_ip": source_ip,
            "threat_actor": ip_db[source_ip]["actor"],
            "ATTACK_campaign": ip_db[source_ip]["campaign"],
            "reputation_score": 9.5
        })
    elif dest_ip in ["185.220.101.5", "45.9.148.15"]:
        ip_db = {
            "185.220.101.5": {"actor": "APT28", "campaign": "Operation Cobalt"},
            "45.9.148.15": {"actor": "Wizard Spider", "campaign": "Ryuk Ransomware"}
        }
        threat.update({
            "IOC_match": True,
            "IOC_value": dest_ip,
            "IOC_type": "IP_ADDRESS",
            "IOC_confidence": 0.85,
            "malicious_ip": dest_ip,
            "threat_actor": ip_db[dest_ip]["actor"],
            "ATTACK_campaign": ip_db[dest_ip]["campaign"],
            "reputation_score": 8.5
        })
    elif file_hash == "44d88612fe583ed3d8151c5f139469a37e974e497920fe1e5c02450d03251d56":
        threat.update({
            "IOC_match": True,
            "IOC_value": file_hash,
            "IOC_type": "HASH",
            "IOC_confidence": 1.0,
            "malicious_hash": file_hash,
            "malware_family": "WannaCry",
            "reputation_score": 10.0
        })

    # Override threat fields if custom kwargs passed
    for key in ["threat_actor", "ATTACK_campaign", "mitre_tactic", "mitre_technique", "mitre_technique_id", "malware_family"]:
        if kwargs.get(key):
            threat[key] = kwargs[key]

    return {
        "event_information": {
            "event_uuid": meta["event_uuid"],
            "original_event_id": meta["original_event_id"],
            "event_type": meta["event_type"],
            "event_category": meta["event_category"],
            "source_system": meta["source_system"],
            "source_vendor": meta["source_vendor"],
            "normalized_timestamp": "2026-07-14T11:15:30Z",
            "original_timestamp": meta["original_timestamp"],
            "ingestion_timestamp": meta["ingestion_timestamp"],
            "processing_timestamp": meta["processing_timestamp"],
            "correlation_id": meta["correlation_id"],
            "batch_id": None,
            "stream_id": None,
            "schema_version": "1.0",
            "pipeline_version": meta["pipeline_version"],
            "processing_status": "SUCCESS",
            "processing_duration_ms": 1.25
        },
        "identity_context": {
            "customer_id": kwargs.get("customer_id"),
            "employee_id": kwargs.get("employee_id"),
            "user_id": kwargs.get("user_id"),
            "username": kwargs.get("username"),
            "account_number": kwargs.get("account_number"),
            "card_number_masked": kwargs.get("card_number_masked"),
            "customer_type": kwargs.get("customer_type"),
            "role": kwargs.get("role"),
            "department": kwargs.get("department"),
            "authentication_method": kwargs.get("authentication_method"),
            "authentication_status": kwargs.get("authentication_status"),
            "mfa_status": kwargs.get("mfa_status")
        },
        "asset_context": {
            "device_id": req_val["entity_context"].get("device_id"),
            "endpoint_id": req_val["entity_context"].get("endpoint_id"),
            "device_type": kwargs.get("device_type"),
            "operating_system": kwargs.get("operating_system"),
            "browser": kwargs.get("browser"),
            "firewall": kwargs.get("firewall"),
            "vpn_gateway": kwargs.get("vpn_gateway"),
            "atm_id": kwargs.get("atm_id"),
            "pos_terminal": kwargs.get("pos_terminal"),
            "server_id": kwargs.get("server_id"),
            "asset_name": kwargs.get("asset_name"),
            "asset_group": kwargs.get("asset_group"),
            "asset_location": kwargs.get("asset_location"),
            "asset_owner": kwargs.get("asset_owner"),
            "asset_criticality": kwargs.get("asset_criticality")
        },
        "network_context": {
            "source_ip": source_ip,
            "destination_ip": dest_ip,
            "public_ip": None if is_private(source_ip) else source_ip,
            "source_port": req_val["network_context"].get("source_port"),
            "destination_port": req_val["network_context"].get("destination_port"),
            "protocol": req_val["network_context"].get("protocol"),
            "country": geo["country"],
            "city": geo["city"],
            "region": geo["region"],
            "network_zone": "Internal" if is_private(source_ip) else "External",
            "vpn_used": geo["geo_source"] == "PrivateIP",
            "proxy_used": False,
            "asn": geo["asn"],
            "isp": geo["isp"],
            "connection_type": None
        },
        "financial_context": {
            "transaction_id": kwargs.get("transaction_id"),
            "transaction_type": kwargs.get("transaction_type"),
            "payment_channel": kwargs.get("payment_channel"),
            "amount": kwargs.get("amount"),
            "currency": kwargs.get("currency"),
            "sender_account": kwargs.get("sender_account"),
            "receiver_account": kwargs.get("receiver_account"),
            "beneficiary_id": kwargs.get("beneficiary_id"),
            "receiver_bank": kwargs.get("receiver_bank"),
            "merchant": kwargs.get("merchant"),
            "merchant_category": kwargs.get("merchant_category"),
            "branch": kwargs.get("branch"),
            "transaction_status": kwargs.get("transaction_status"),
            "account_balance": kwargs.get("account_balance"),
            "approval_code": kwargs.get("approval_code"),
            "ifsc": kwargs.get("ifsc")
        },
        "security_context": {
            "severity": "HIGH" if threat["IOC_match"] else req_val["security_context"].get("severity", "LOW"),
            "action": req_val["security_context"].get("action"),
            "attack_name": kwargs.get("attack_name"),
            "signature": kwargs.get("signature"),
            "signature_id": req_val["security_context"].get("signature_id"),
            "rule_name": kwargs.get("rule_name"),
            "rule_id": req_val["security_context"].get("rule_id"),
            "sensor_id": req_val["security_context"].get("sensor_id"),
            "log_source": req_val["security_context"].get("log_source"),
            "malware_name": kwargs.get("malware_name"),
            "process_name": kwargs.get("process_name"),
            "process_hash": kwargs.get("process_hash"),
            "detection_status": kwargs.get("detection_status"),
            "encryption_status": kwargs.get("encryption_status"),
            "cpu_usage": kwargs.get("cpu_usage"),
            "memory_usage": kwargs.get("memory_usage")
        },
        "threat_context": threat,
        "fraud_context": {
            "high_risk_beneficiary": kwargs.get("high_risk_beneficiary", False),
            "mule_account": kwargs.get("mule_account", False),
            "blacklisted_account": kwargs.get("blacklisted_account", False),
            "high_risk_country": kwargs.get("high_risk_country", False),
            "risky_merchant": kwargs.get("risky_merchant", False),
            "first_time_payee": kwargs.get("first_time_payee", False),
            "rapid_beneficiary_addition": kwargs.get("rapid_beneficiary_addition", False),
            "unusual_transaction_pattern": kwargs.get("unusual_transaction_pattern", False),
            "velocity_indicator": kwargs.get("velocity_indicator", 0.0),
            "large_transfer": kwargs.get("large_transfer", False),
            "new_payee": kwargs.get("new_payee", False),
            "new_merchant": kwargs.get("new_merchant", False)
        },
        "geo_context": geo,
        "behavioral_features": {
            "new_device": kwargs.get("new_device", False),
            "new_location": kwargs.get("new_location", False),
            "first_login_today": kwargs.get("first_login_today", False),
            "unusual_login_hour": kwargs.get("unusual_login_hour", False),
            "multiple_failed_logins": kwargs.get("multiple_failed_logins", False),
            "high_transaction_amount": kwargs.get("high_transaction_amount", False),
            "repeated_transactions": kwargs.get("repeated_transactions", False),
            "foreign_transaction": kwargs.get("foreign_transaction", False),
            "multiple_atm_usage": kwargs.get("multiple_atm_usage", False),
            "new_browser": kwargs.get("new_browser", False),
            "new_operating_system": kwargs.get("new_operating_system", False),
            "abnormal_cpu_usage": kwargs.get("abnormal_cpu_usage", False),
            "abnormal_memory_usage": kwargs.get("abnormal_memory_usage", False),
            "large_archive_access": kwargs.get("large_archive_access", False),
            "bulk_encrypted_transfer": kwargs.get("bulk_encrypted_transfer", False),
            "possible_impossible_travel": kwargs.get("possible_impossible_travel", False),
            "new_beneficiary": kwargs.get("new_beneficiary", False),
            "new_ip": kwargs.get("new_ip", False),
            "new_network": kwargs.get("new_network", False)
        },
        "relationship_context": {
            "customer_id": kwargs.get("customer_id"),
            "employee_id": kwargs.get("employee_id"),
            "session_id": req_val["entity_context"].get("session_id"),
            "device_id": req_val["entity_context"].get("device_id"),
            "endpoint_id": req_val["entity_context"].get("endpoint_id"),
            "beneficiary_id": kwargs.get("beneficiary_id"),
            "transaction_id": kwargs.get("transaction_id"),
            "parent_event": None,
            "linked_events": [],
            "relationship_keys": kwargs.get("relationship_keys", {}),
            "identity_chain": kwargs.get("identity_chain", []),
            "asset_chain": kwargs.get("asset_chain", []),
            "transaction_chain": kwargs.get("transaction_chain", [])
        },
        "normalized_event_data": normalized_event_data
    }

# ==========================================
# PART 1: REQUEST EXAMPLES (Module 1 Output)
# ==========================================

REQUEST_EXAMPLES: Dict[str, Dict[str, Any]] = {
    "Firewall": {
        "summary": "Firewall Block Event",
        "value": {
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
    },
    "IDS": {
        "summary": "IDS Signature Alert Event",
        "value": {
            "metadata": {
                "event_uuid": "d2b90c12-32b4-4b5c-a67e-1289cf012346",
                "original_event_id": "snort-alert-4421",
                "event_type": "IDS",
                "event_category": "intrusion",
                "source_system": "Snort-IDS-HQ",
                "source_vendor": "Cisco",
                "ingestion_timestamp": "2026-07-14T11:20:05Z",
                "original_timestamp": "2026-07-14T11:20:04Z",
                "processing_timestamp": "2026-07-14T11:20:06Z",
                "validation_status": "VALID",
                "duplicate_status": "UNIQUE",
                "schema_version": "1.0",
                "event_hash": "b5g89d023b1287eac901b223cde897f2",
                "correlation_id": "c0a2103f-9812-4210-b982-f091c8901235",
                "pipeline_version": "1.0.0",
                "processing_status": "PENDING"
            },
            "entity_context": {
                "device_id": "dev-web-server-01"
            },
            "network_context": {
                "source_ip": "45.9.148.15",
                "destination_ip": "10.0.1.10",
                "source_port": 49152,
                "destination_port": 80,
                "protocol": "TCP"
            },
            "security_context": {
                "severity": "CRITICAL",
                "action": "ALERT",
                "rule_id": "sig-10029",
                "sensor_id": "sensor-snort-dmz",
                "signature_id": "3201-SQL-Injection-Attempt",
                "log_source": "IDS"
            },
            "raw_payload": {
                "Source_IP": "45.9.148.15",
                "Destination_IP": "10.0.1.10",
                "SOURCE_PORT": "49152",
                "DESTINATION_PORT": "80",
                "Protocol": "TCP",
                "Action": "ALERT",
                "Signature_ID": "3201",
                "Attack_Name": "SQL Injection Attempt"
            }
        }
    },
    "VPN": {
        "summary": "VPN Remote Login Event",
        "value": {
            "metadata": {
                "event_uuid": "f3c90c12-32b4-4b5c-a67e-1289cf012347",
                "original_event_id": "vpn-session-882",
                "event_type": "VPN",
                "event_category": "access",
                "source_system": "ASA-VPN-Gateway",
                "source_vendor": "Cisco",
                "ingestion_timestamp": "2026-07-14T11:22:15Z",
                "original_timestamp": "2026-07-14T11:22:14Z",
                "processing_timestamp": "2026-07-14T11:22:16Z",
                "validation_status": "VALID",
                "duplicate_status": "UNIQUE",
                "schema_version": "1.0",
                "event_hash": "c6h89d023b1287eac901b223cde897f3",
                "correlation_id": "c0a2103f-9812-4210-b982-f091c8901236",
                "pipeline_version": "1.0.0",
                "processing_status": "PENDING"
            },
            "entity_context": {
                "employee_id": "EMP-908",
                "device_id": "dev-corp-laptop-102"
            },
            "network_context": {
                "source_ip": "8.8.8.8",
                "destination_ip": "192.168.1.1",
                "source_port": 52190,
                "destination_port": 443,
                "protocol": "TCP"
            },
            "security_context": {
                "severity": "LOW",
                "action": "ALLOW",
                "sensor_id": "sensor-vpn-west",
                "log_source": "VPN"
            },
            "raw_payload": {
                "Client_IP": "8.8.8.8",
                "VPN Gateway": "gateway-west-1",
                "Authentication": "SUCCESS",
                "MFA": "DUO_PUSH",
                "DeviceID": "dev-corp-laptop-102",
                "username": "alice_emp"
            }
        }
    },
    "IAM": {
        "summary": "IAM Portal Login Event",
        "value": {
            "metadata": {
                "event_uuid": "a4d90c12-32b4-4b5c-a67e-1289cf012348",
                "original_event_id": "iam-auth-1092",
                "event_type": "IAM",
                "event_category": "authentication",
                "source_system": "Okta-IAM",
                "source_vendor": "Okta",
                "ingestion_timestamp": "2026-07-14T11:25:00Z",
                "original_timestamp": "2026-07-14T11:24:59Z",
                "processing_timestamp": "2026-07-14T11:25:01Z",
                "validation_status": "VALID",
                "duplicate_status": "UNIQUE",
                "schema_version": "1.0",
                "event_hash": "d7i89d023b1287eac901b223cde897f4",
                "correlation_id": "c0a2103f-9812-4210-b982-f091c8901237",
                "pipeline_version": "1.0.0",
                "processing_status": "PENDING"
            },
            "entity_context": {
                "employee_id": "EMP-908",
                "session_id": "sess-okta-8871"
            },
            "network_context": {
                "source_ip": "106.51.78.23",
                "destination_ip": "192.168.1.10",
                "protocol": "HTTPS"
            },
            "security_context": {
                "severity": "LOW",
                "action": "ALLOW",
                "sensor_id": "sensor-okta-api",
                "log_source": "IAM"
            },
            "raw_payload": {
                "IP": "106.51.78.23",
                "Authentication_Method": "PASSWORD_MFA",
                "Login_Status": "SUCCESS",
                "MFA": "GOOGLE_AUTHENTICATOR",
                "username": "alice_emp"
            }
        }
    },
    "InternetBanking": {
        "summary": "Internet Banking Portal Login Event",
        "value": {
            "metadata": {
                "event_uuid": "b5e90c12-32b4-4b5c-a67e-1289cf012349",
                "original_event_id": "portal-login-0912",
                "event_type": "INTERNET_BANKING",
                "event_category": "banking_portal",
                "source_system": "FALCON-Portal",
                "source_vendor": "FALCON",
                "ingestion_timestamp": "2026-07-14T11:30:10Z",
                "original_timestamp": "2026-07-14T11:30:09Z",
                "processing_timestamp": "2026-07-14T11:30:11Z",
                "validation_status": "VALID",
                "duplicate_status": "UNIQUE",
                "schema_version": "1.0",
                "event_hash": "e8j89d023b1287eac901b223cde897f5",
                "correlation_id": "c0a2103f-9812-4210-b982-f091c8901238",
                "pipeline_version": "1.0.0",
                "processing_status": "PENDING"
            },
            "entity_context": {
                "customer_id": "CUST-A",
                "session_id": "sess-portal-4421"
            },
            "network_context": {
                "source_ip": "106.51.78.23",
                "protocol": "HTTPS"
            },
            "security_context": {
                "severity": "LOW",
                "action": "ALLOW",
                "sensor_id": "sensor-portal-web",
                "log_source": "InternetBanking"
            },
            "raw_payload": {
                "IP": "106.51.78.23",
                "Browser": "Chrome Mobile",
                "OS": "Android",
                "Login_Status": "SUCCESS",
                "GPS": "12.9716,77.5946",
                "username": "alice_user"
            }
        }
    },
    "CoreBanking": {
        "summary": "Core Banking Ledger Update",
        "value": {
            "metadata": {
                "event_uuid": "c6f90c12-32b4-4b5c-a67e-1289cf012350",
                "original_event_id": "ledger-txn-9011",
                "event_type": "CORE_BANKING",
                "event_category": "banking_ledger",
                "source_system": "FALCON-Core-Ledger",
                "source_vendor": "FALCON",
                "ingestion_timestamp": "2026-07-14T11:32:00Z",
                "original_timestamp": "2026-07-14T11:31:59Z",
                "processing_timestamp": "2026-07-14T11:32:01Z",
                "validation_status": "VALID",
                "duplicate_status": "UNIQUE",
                "schema_version": "1.0",
                "event_hash": "f9k89d023b1287eac901b223cde897f6",
                "correlation_id": "c0a2103f-9812-4210-b982-f091c8901239",
                "pipeline_version": "1.0.0",
                "processing_status": "PENDING"
            },
            "entity_context": {
                "customer_id": "CUST-A",
                "account_number": "ACC-9911",
                "transaction_id": "TXN-901"
            },
            "network_context": {
                "source_ip": "10.0.10.15",
                "protocol": "TCP"
            },
            "security_context": {
                "severity": "LOW",
                "action": "ALLOW",
                "sensor_id": "sensor-core-ledger",
                "log_source": "CoreBanking"
            },
            "raw_payload": {
                "Transaction_ID": "TXN-901",
                "Transaction_Type": "TRANSFER",
                "Amount": "600000.0",
                "Currency": "INR",
                "account_number": "ACC-9911",
                "receiver_account": "ACC-BOB-02",
                "Balance_After": "1500000.0",
                "Status": "SUCCESS",
                "Branch": "Bengaluru-HQ"
            }
        }
    },
    "UPI": {
        "summary": "UPI Instant Money Transfer",
        "value": {
            "metadata": {
                "event_uuid": "d7g90c12-32b4-4b5c-a67e-1289cf012351",
                "original_event_id": "upi-gpay-4412",
                "event_type": "UPI",
                "event_category": "banking_payment",
                "source_system": "UPI-Gateway",
                "source_vendor": "NPCI",
                "ingestion_timestamp": "2026-07-14T11:35:10Z",
                "original_timestamp": "2026-07-14T11:35:09Z",
                "processing_timestamp": "2026-07-14T11:35:11Z",
                "validation_status": "VALID",
                "duplicate_status": "UNIQUE",
                "schema_version": "1.0",
                "event_hash": "g0l89d023b1287eac901b223cde897f7",
                "correlation_id": "c0a2103f-9812-4210-b982-f091c8901240",
                "pipeline_version": "1.0.0",
                "processing_status": "PENDING"
            },
            "entity_context": {
                "customer_id": "CUST-A",
                "account_number": "ACC-9911"
            },
            "network_context": {
                "source_ip": "106.51.78.23",
                "protocol": "HTTPS"
            },
            "security_context": {
                "severity": "LOW",
                "action": "ALLOW",
                "sensor_id": "sensor-upi-api",
                "log_source": "UPI"
            },
            "raw_payload": {
                "Transaction_ID": "TXN-902",
                "UPI_ID": "alice@okaxis",
                "Sender_Account": "ACC-9911",
                "Receiver_UPI": "bob@okaxis",
                "Receiver_Bank": "Axis Bank",
                "Amount": "25000",
                "Status": "SUCCESS"
            }
        }
    },
    "NEFT": {
        "summary": "NEFT Ledger Transfer",
        "value": {
            "metadata": {
                "event_uuid": "e8h90c12-32b4-4b5c-a67e-1289cf012352",
                "original_event_id": "neft-out-002",
                "event_type": "NEFT",
                "event_category": "banking_transfer",
                "source_system": "NEFT-Gateway-Router",
                "source_vendor": "RBI",
                "ingestion_timestamp": "2026-07-14T11:40:00Z",
                "original_timestamp": "2026-07-14T11:39:59Z",
                "processing_timestamp": "2026-07-14T11:40:01Z",
                "validation_status": "VALID",
                "duplicate_status": "UNIQUE",
                "schema_version": "1.0",
                "event_hash": "h1m89d023b1287eac901b223cde897f8",
                "correlation_id": "c0a2103f-9812-4210-b982-f091c8901241",
                "pipeline_version": "1.0.0",
                "processing_status": "PENDING"
            },
            "entity_context": {
                "customer_id": "CUST-A",
                "account_number": "ACC-9911"
            },
            "network_context": {
                "source_ip": "10.0.12.1",
                "protocol": "TCP"
            },
            "security_context": {
                "severity": "LOW",
                "action": "ALLOW",
                "sensor_id": "sensor-neft-gw",
                "log_source": "NEFT"
            },
            "raw_payload": {
                "Transaction_ID": "NEFT-10021",
                "Sender_Account": "ACC-9911",
                "Receiver_Account": "ACC-BOB-02",
                "Receiver_Bank": "HDFC Bank",
                "Receiver_IFSC": "HDFC0000102",
                "Amount": "45000",
                "Status": "SUCCESS"
            }
        }
    },
    "RTGS": {
        "summary": "RTGS High Value Transfer",
        "value": {
            "metadata": {
                "event_uuid": "f9i90c12-32b4-4b5c-a67e-1289cf012353",
                "original_event_id": "rtgs-out-102",
                "event_type": "RTGS",
                "event_category": "banking_transfer",
                "source_system": "RTGS-Gateway-Router",
                "source_vendor": "RBI",
                "ingestion_timestamp": "2026-07-14T11:45:00Z",
                "original_timestamp": "2026-07-14T11:44:59Z",
                "processing_timestamp": "2026-07-14T11:45:01Z",
                "validation_status": "VALID",
                "duplicate_status": "UNIQUE",
                "schema_version": "1.0",
                "event_hash": "i2n89d023b1287eac901b223cde897f9",
                "correlation_id": "c0a2103f-9812-4210-b982-f091c8901242",
                "pipeline_version": "1.0.0",
                "processing_status": "PENDING"
            },
            "entity_context": {
                "customer_id": "CUST-A",
                "account_number": "ACC-9911"
            },
            "network_context": {
                "source_ip": "10.0.12.1",
                "protocol": "TCP"
            },
            "security_context": {
                "severity": "LOW",
                "action": "ALLOW",
                "sensor_id": "sensor-rtgs-gw",
                "log_source": "RTGS"
            },
            "raw_payload": {
                "Transaction_ID": "RTGS-20092",
                "Sender_Account": "ACC-9911",
                "Receiver_Account": "ACC-MULE-882",
                "Receiver_Bank": "State Bank of India",
                "Receiver_IFSC": "SBIN0002931",
                "Amount": "2500000",
                "Status": "SUCCESS"
            }
        }
    },
    "IMPS": {
        "summary": "IMPS Instant Ledger Transfer",
        "value": {
            "metadata": {
                "event_uuid": "a0j90c12-32b4-4b5c-a67e-1289cf012354",
                "original_event_id": "imps-out-442",
                "event_type": "IMPS",
                "event_category": "banking_transfer",
                "source_system": "IMPS-Switch",
                "source_vendor": "NPCI",
                "ingestion_timestamp": "2026-07-14T11:47:00Z",
                "original_timestamp": "2026-07-14T11:46:59Z",
                "processing_timestamp": "2026-07-14T11:47:01Z",
                "validation_status": "VALID",
                "duplicate_status": "UNIQUE",
                "schema_version": "1.0",
                "event_hash": "j3o89d023b1287eac901b223cde897fa",
                "correlation_id": "c0a2103f-9812-4210-b982-f091c8901243",
                "pipeline_version": "1.0.0",
                "processing_status": "PENDING"
            },
            "entity_context": {
                "customer_id": "CUST-A",
                "account_number": "ACC-9911"
            },
            "network_context": {
                "source_ip": "106.51.78.23",
                "protocol": "HTTPS"
            },
            "security_context": {
                "severity": "LOW",
                "action": "ALLOW",
                "sensor_id": "sensor-imps-switch",
                "log_source": "IMPS"
            },
            "raw_payload": {
                "Transaction_ID": "IMPS-90182",
                "Sender_Account": "ACC-9911",
                "Receiver_Account": "ACC-BOB-02",
                "Receiver_Bank": "ICICI Bank",
                "Receiver_IFSC": "ICIC0001092",
                "Amount": "15000",
                "Status": "SUCCESS"
            }
        }
    },
    "Card": {
        "summary": "Card POS Transaction",
        "value": {
            "metadata": {
                "event_uuid": "b1k90c12-32b4-4b5c-a67e-1289cf012355",
                "original_event_id": "card-auth-7721",
                "event_type": "CARD",
                "event_category": "banking_payment",
                "source_system": "POS-Merchant-101",
                "source_vendor": "Verifone",
                "ingestion_timestamp": "2026-07-14T11:50:00Z",
                "original_timestamp": "2026-07-14T11:49:59Z",
                "processing_timestamp": "2026-07-14T11:50:01Z",
                "validation_status": "VALID",
                "duplicate_status": "UNIQUE",
                "schema_version": "1.0",
                "event_hash": "k4p89d023b1287eac901b223cde897fb",
                "correlation_id": "c0a2103f-9812-4210-b982-f091c8901244",
                "pipeline_version": "1.0.0",
                "processing_status": "PENDING"
            },
            "entity_context": {
                "customer_id": "CUST-A",
                "account_number": "ACC-9911"
            },
            "network_context": {
                "source_ip": "106.51.78.23",
                "protocol": "HTTPS"
            },
            "security_context": {
                "severity": "LOW",
                "action": "ALLOW",
                "sensor_id": "sensor-card-pos",
                "log_source": "Card"
            },
            "raw_payload": {
                "Transaction_ID": "TXN_77261",
                "Card_Number": "411111XXXXXX1111",
                "MCC": "5411",
                "Merchant": "evil-gambling.com",
                "Amount": "25000",
                "Status": "SUCCESS",
                "Card_Country": "Russia",
                "Card_City": "Moscow",
                "latitude": "55.7558",
                "longitude": "37.6173",
                "POS_Terminal": "POS-TERM-MOSCOW-01"
            }
        }
    },
    "ATM": {
        "summary": "ATM Physical Cash Withdrawal",
        "value": {
            "metadata": {
                "event_uuid": "c2l90c12-32b4-4b5c-a67e-1289cf012356",
                "original_event_id": "atm-withdraw-4421",
                "event_type": "ATM",
                "event_category": "banking_atm",
                "source_system": "ATM-BLR-04",
                "source_vendor": "NCR",
                "ingestion_timestamp": "2026-07-14T11:55:00Z",
                "original_timestamp": "2026-07-14T11:54:59Z",
                "processing_timestamp": "2026-07-14T11:55:01Z",
                "validation_status": "VALID",
                "duplicate_status": "UNIQUE",
                "schema_version": "1.0",
                "event_hash": "l5q89d023b1287eac901b223cde897fc",
                "correlation_id": "c0a2103f-9812-4210-b982-f091c8901245",
                "pipeline_version": "1.0.0",
                "processing_status": "PENDING"
            },
            "entity_context": {
                "customer_id": "CUST-A",
                "account_number": "ACC-9911"
            },
            "network_context": {
                "source_ip": "10.12.90.1",
                "protocol": "TCP"
            },
            "security_context": {
                "severity": "LOW",
                "action": "ALLOW",
                "sensor_id": "sensor-atm-firmware",
                "log_source": "ATM"
            },
            "raw_payload": {
                "Transaction_ID": "TXN-904",
                "ATM_ID": "ATM-BLR-04",
                "Amount": "10000",
                "Card_Number": "411111XXXXXX1111",
                "Status": "SUCCESS",
                "ATM_Location": "Bengaluru MG Road",
                "GPS": "12.9716,77.5946"
            }
        }
    },
    "Beneficiary": {
        "summary": "Beneficiary Configuration Update",
        "value": {
            "metadata": {
                "event_uuid": "d3m90c12-32b4-4b5c-a67e-1289cf012357",
                "original_event_id": "benef-add-102",
                "event_type": "BENEFICIARY",
                "event_category": "banking_portal",
                "source_system": "FALCON-Portal",
                "source_vendor": "FALCON",
                "ingestion_timestamp": "2026-07-14T12:00:00Z",
                "original_timestamp": "2026-07-14T11:59:59Z",
                "processing_timestamp": "2026-07-14T12:00:01Z",
                "validation_status": "VALID",
                "duplicate_status": "UNIQUE",
                "schema_version": "1.0",
                "event_hash": "m6r89d023b1287eac901b223cde897fd",
                "correlation_id": "c0a2103f-9812-4210-b982-f091c8901246",
                "pipeline_version": "1.0.0",
                "processing_status": "PENDING"
            },
            "entity_context": {
                "customer_id": "CUST-A",
                "account_number": "ACC-9911"
            },
            "network_context": {
                "source_ip": "106.51.78.23",
                "protocol": "HTTPS"
            },
            "security_context": {
                "severity": "LOW",
                "action": "ALLOW",
                "sensor_id": "sensor-portal-web",
                "log_source": "Beneficiary"
            },
            "raw_payload": {
                "Beneficiary_ID": "BEN-BOB",
                "Beneficiary_Name": "Bob Smith",
                "Beneficiary_Account": "ACC-BOB-02",
                "Beneficiary_Bank": "HDFC Bank",
                "Operation_Type": "ADD"
            }
        }
    },
    "EDR": {
        "summary": "EDR Process Injection Malware Detected",
        "value": {
            "metadata": {
                "event_uuid": "e4n90c12-32b4-4b5c-a67e-1289cf012358",
                "original_event_id": "cs-agent-alert-87721",
                "event_type": "EDR",
                "event_category": "endpoint_alert",
                "source_system": "CrowdStrike-Agent-HQ",
                "source_vendor": "CrowdStrike",
                "ingestion_timestamp": "2026-07-14T12:05:00Z",
                "original_timestamp": "2026-07-14T12:04:59Z",
                "processing_timestamp": "2026-07-14T12:05:01Z",
                "validation_status": "VALID",
                "duplicate_status": "UNIQUE",
                "schema_version": "1.0",
                "event_hash": "n7s89d023b1287eac901b223cde897fe",
                "correlation_id": "c0a2103f-9812-4210-b982-f091c8901247",
                "pipeline_version": "1.0.0",
                "processing_status": "PENDING"
            },
            "entity_context": {
                "employee_id": "EMP-908"
            },
            "network_context": {
                "source_ip": "192.168.10.88",
                "protocol": "TCP"
            },
            "security_context": {
                "severity": "CRITICAL",
                "action": "BLOCK",
                "sensor_id": "sensor-cs-corp-laptop",
                "log_source": "EDR"
            },
            "raw_payload": {
                "Host_Name": "EMP-LAPTOP-102",
                "Process_Name": "powershell.exe",
                "Process_Hash": "44d88612fe583ed3d8151c5f139469a37e974e497920fe1e5c02450d03251d56",
                "Malware_Name": "WannaCry.ProcessInjection",
                "Detection_Status": "BLOCKED",
                "CPU_Usage": "95%",
                "Memory_Usage": "91%"
            }
        }
    },
    "SIEM": {
        "summary": "SIEM Aggregated Alarm Alert",
        "value": {
            "metadata": {
                "event_uuid": "f5o90c12-32b4-4b5c-a67e-1289cf012359",
                "original_event_id": "splunk-rule-99182",
                "event_type": "SIEM",
                "event_category": "threat_correlation",
                "source_system": "Splunk-SIEM-HQ",
                "source_vendor": "Splunk",
                "ingestion_timestamp": "2026-07-14T12:10:00Z",
                "original_timestamp": "2026-07-14T12:09:59Z",
                "processing_timestamp": "2026-07-14T12:10:01Z",
                "validation_status": "VALID",
                "duplicate_status": "UNIQUE",
                "schema_version": "1.0",
                "event_hash": "o8t89d023b1287eac901b223cde897ff",
                "correlation_id": "c0a2103f-9812-4210-b982-f091c8901248",
                "pipeline_version": "1.0.0",
                "processing_status": "PENDING"
            },
            "entity_context": {
                "employee_id": "EMP-908"
            },
            "network_context": {
                "source_ip": "185.220.101.5",
                "destination_ip": "10.0.1.5",
                "protocol": "TCP"
            },
            "security_context": {
                "severity": "HIGH",
                "action": "BLOCK",
                "rule_id": "rule-excessive-logins-tor",
                "sensor_id": "sensor-splunk-index-west",
                "log_source": "SIEM"
            },
            "raw_payload": {
                "Correlation_ID": "rule-excessive-logins-tor",
                "Correlation_Rule_Name": "Excessive Failed Logins From Tor Exit Node",
                "Attack_Category": "Initial Access",
                "Source_IP": "185.220.101.5",
                "Destination_IP": "10.0.1.5"
            }
        }
    },
    "ThreatFeed": {
        "summary": "Threat Intel Feed OSINT Log",
        "value": {
            "metadata": {
                "event_uuid": "a6p90c12-32b4-4b5c-a67e-1289cf012360",
                "original_event_id": "threat-intel-osint-44",
                "event_type": "THREAT_FEED",
                "event_category": "threat_intelligence",
                "source_system": "OSINT-Threat-Feeds",
                "source_vendor": "Anomali",
                "ingestion_timestamp": "2026-07-14T12:15:00Z",
                "original_timestamp": "2026-07-14T12:14:59Z",
                "processing_timestamp": "2026-07-14T12:15:01Z",
                "validation_status": "VALID",
                "duplicate_status": "UNIQUE",
                "schema_version": "1.0",
                "event_hash": "p9u89d023b1287eac901b223cde897fg",
                "correlation_id": "c0a2103f-9812-4210-b982-f091c8901249",
                "pipeline_version": "1.0.0",
                "processing_status": "PENDING"
            },
            "entity_context": {},
            "network_context": {
                "source_ip": "45.9.148.15",
                "protocol": "TCP"
            },
            "security_context": {
                "severity": "HIGH",
                "action": "ALERT",
                "sensor_id": "sensor-threat-intel-engine",
                "log_source": "ThreatFeed"
            },
            "raw_payload": {
                "IOC_Value": "45.9.148.15",
                "IOC_Type": "IP_ADDRESS",
                "Threat_Actor": "Wizard Spider",
                "Campaign": "Ryuk Ransomware",
                "Malware_Family": "Ryuk",
                "Confidence": "0.95"
            }
        }
    },
    "Quantum": {
        "summary": "Quantum Post-Quantum Cryptography Audit",
        "value": {
            "metadata": {
                "event_uuid": "b7q90c12-32b4-4b5c-a67e-1289cf012361",
                "original_event_id": "pqc-kem-tls-098",
                "event_type": "QUANTUM",
                "event_category": "cryptography_audit",
                "source_system": "Quantum-Sensors-HQ",
                "source_vendor": "FALCON",
                "ingestion_timestamp": "2026-07-14T12:20:00Z",
                "original_timestamp": "2026-07-14T12:19:59Z",
                "processing_timestamp": "2026-07-14T12:20:01Z",
                "validation_status": "VALID",
                "duplicate_status": "UNIQUE",
                "schema_version": "1.0",
                "event_hash": "q0v89d023b1287eac901b223cde897fh",
                "correlation_id": "c0a2103f-9812-4210-b982-f091c8901250",
                "pipeline_version": "1.0.0",
                "processing_status": "PENDING"
            },
            "entity_context": {
                "employee_id": "EMP-908"
            },
            "network_context": {
                "source_ip": "192.168.1.45",
                "destination_ip": "10.0.1.5",
                "source_port": 54312,
                "destination_port": 443,
                "protocol": "KEM_TLS"
            },
            "security_context": {
                "severity": "MEDIUM",
                "action": "ALLOW",
                "sensor_id": "sensor-pqc-kem",
                "log_source": "Quantum"
            },
            "raw_payload": {
                "Anomaly_Type": "HNDL_suspected",
                "Crypto_Algorithm": "Kyber768",
                "Transfer_Size": "5368709120",
                "Transfer_Time": "150.5",
                "SRC_IP": "192.168.1.45",
                "DST_IP": "10.0.1.5",
                "SOURCE_PORT": "54312",
                "DESTINATION_PORT": "443"
            }
        }
    }
}

# ==========================================
# PART 2: RESPONSE EXAMPLES (Module 2 Output)
# ==========================================

RESPONSE_EXAMPLES: Dict[str, Dict[str, Any]] = {
    "Firewall": {
        "summary": "Firewall Block Enriched Event",
        "value": _base_response(
            REQUEST_EXAMPLES["Firewall"]["value"],
            normalized_event_data={
                "source_ip": "192.168.1.45",
                "destination_ip": "185.220.101.5",
                "source_port": 54129,
                "destination_port": 443,
                "protocol": "TCP",
                "action": "BLOCK",
                "rule_id": "deny-malicious-outbound",
                "bytes_sent": 1500,
                "bytes_received": 0
            },
            device_type="Firewall",
            firewall="deny-malicious-outbound",
            mitre_tactic="Command and Control",
            mitre_technique="Application Layer Protocol",
            mitre_technique_id="T1071",
            relationship_keys={
                "device_session": "dev-corp-laptop-102:::sess-corp-9912",
                "account_beneficiary": "None:::None"
            },
            identity_chain=["ip:192.168.1.45"],
            asset_chain=["device:dev-corp-laptop-102"]
        )
    },
    "IDS": {
        "summary": "IDS Alert Enriched Event",
        "value": _base_response(
            REQUEST_EXAMPLES["IDS"]["value"],
            normalized_event_data={
                "source_ip": "45.9.148.15",
                "destination_ip": "10.0.1.10",
                "source_port": 49152,
                "destination_port": 80,
                "protocol": "TCP",
                "signature_id": "3201-SQL-Injection-Attempt",
                "attack_name": "SQL Injection Attempt"
            },
            device_type="IDS",
            mitre_tactic="Execution",
            mitre_technique="User Execution",
            mitre_technique_id="T1204",
            relationship_keys={"endpoint_process": "None:::None"},
            identity_chain=["ip:45.9.148.15"],
            asset_chain=[]
        )
    },
    "VPN": {
        "summary": "VPN Remote Login Enriched Event",
        "value": _base_response(
            REQUEST_EXAMPLES["VPN"]["value"],
            normalized_event_data={
                "source_ip": "8.8.8.8",
                "vpn_gateway": "gateway-west-1",
                "authentication_status": "SUCCESS",
                "mfa_status": "DUO_PUSH"
            },
            employee_id="EMP-908",
            username="alice_emp",
            device_type="VPN Gateway",
            vpn_gateway="gateway-west-1",
            vpn_used=True,
            mfa_status="DUO_PUSH",
            authentication_status="SUCCESS",
            relationship_keys={},
            identity_chain=["employee:EMP-908", "user:alice_emp", "ip:8.8.8.8"],
            asset_chain=["device:dev-corp-laptop-102"]
        )
    },
    "IAM": {
        "summary": "IAM Portal Login Enriched Event",
        "value": _base_response(
            REQUEST_EXAMPLES["IAM"]["value"],
            normalized_event_data={
                "username": "alice_emp",
                "authentication_method": "PASSWORD_MFA",
                "authentication_status": "SUCCESS",
                "mfa_status": "GOOGLE_AUTHENTICATOR"
            },
            employee_id="EMP-908",
            username="alice_emp",
            device_type="IAM System",
            authentication_method="PASSWORD_MFA",
            authentication_status="SUCCESS",
            mfa_status="GOOGLE_AUTHENTICATOR",
            relationship_keys={},
            identity_chain=["employee:EMP-908", "user:alice_emp", "ip:106.51.78.23"],
            asset_chain=[]
        )
    },
    "InternetBanking": {
        "summary": "Internet Banking Portal Enriched Event",
        "value": _base_response(
            REQUEST_EXAMPLES["InternetBanking"]["value"],
            normalized_event_data={
                "customer_id": "CUST-A",
                "account_number": None,
                "authentication_status": "SUCCESS",
                "ip_address": "106.51.78.23"
            },
            customer_id="CUST-A",
            username="alice_user",
            device_type="Web Browser",
            browser="Chrome Mobile",
            operating_system="Android",
            authentication_status="SUCCESS",
            relationship_keys={"customer_session": "CUST-A:::sess-portal-4421"},
            identity_chain=["customer:CUST-A", "user:alice_user", "ip:106.51.78.23"],
            asset_chain=[]
        )
    },
    "CoreBanking": {
        "summary": "Core Banking Ledger Enriched Event",
        "value": _base_response(
            REQUEST_EXAMPLES["CoreBanking"]["value"],
            normalized_event_data={
                "transaction_id": "TXN-901",
                "account_number": "ACC-9911",
                "amount": 600000.0,
                "currency": "INR",
                "transaction_status": "SUCCESS"
            },
            customer_id="CUST-A",
            account_number="ACC-9911",
            transaction_id="TXN-901",
            sender_account="ACC-9911",
            receiver_account="ACC-BOB-02",
            amount=600000.0,
            currency="INR",
            transaction_type="TRANSFER",
            transaction_status="SUCCESS",
            branch="Bengaluru-HQ",
            large_transfer=True,
            relationship_keys={"customer_account": "CUST-A:::ACC-9911"},
            identity_chain=["customer:CUST-A"],
            asset_chain=[],
            transaction_chain=["account:ACC-9911", "transaction:TXN-901"]
        )
    },
    "UPI": {
        "summary": "UPI Payment Enriched Event",
        "value": _base_response(
            REQUEST_EXAMPLES["UPI"]["value"],
            normalized_event_data={
                "transaction_id": "TXN-902",
                "upi_id": "alice@okaxis",
                "amount": 25000.0,
                "sender_account": "ACC-9911",
                "receiver_upi": "bob@okaxis",
                "receiver_bank": "Axis Bank",
                "merchant": None
            },
            customer_id="CUST-A",
            account_number="ACC-9911",
            sender_account="ACC-9911",
            beneficiary_id="bob@okaxis",
            amount=25000.0,
            currency="INR",
            payment_channel="UPI",
            transaction_status="SUCCESS",
            relationship_keys={"customer_account": "CUST-A:::ACC-9911"},
            identity_chain=["customer:CUST-A"],
            asset_chain=[],
            transaction_chain=["account:ACC-9911", "beneficiary:bob@okaxis"]
        )
    },
    "NEFT": {
        "summary": "NEFT Ledger Enriched Event",
        "value": _base_response(
            REQUEST_EXAMPLES["NEFT"]["value"],
            normalized_event_data={
                "transaction_id": "NEFT-10021",
                "amount": 45000.0,
                "sender_account": "ACC-9911",
                "receiver_account": "ACC-BOB-02",
                "receiver_bank": "HDFC Bank",
                "ifsc": "HDFC0000102"
            },
            customer_id="CUST-A",
            account_number="ACC-9911",
            sender_account="ACC-9911",
            receiver_account="ACC-BOB-02",
            receiver_bank="HDFC Bank",
            ifsc="HDFC0000102",
            amount=45000.0,
            currency="INR",
            payment_channel="NEFT",
            transaction_status="SUCCESS",
            relationship_keys={"customer_account": "CUST-A:::ACC-9911"},
            identity_chain=["customer:CUST-A"],
            asset_chain=[],
            transaction_chain=["account:ACC-9911", "beneficiary:ACC-BOB-02"]
        )
    },
    "RTGS": {
        "summary": "RTGS High Value Enriched Event",
        "value": _base_response(
            REQUEST_EXAMPLES["RTGS"]["value"],
            normalized_event_data={
                "transaction_id": "RTGS-20092",
                "amount": 2500000.0,
                "sender_account": "ACC-9911",
                "receiver_account": "ACC-MULE-882",
                "receiver_bank": "State Bank of India",
                "ifsc": "SBIN0002931"
            },
            customer_id="CUST-A",
            account_number="ACC-9911",
            sender_account="ACC-9911",
            receiver_account="ACC-MULE-882",
            receiver_bank="State Bank of India",
            ifsc="SBIN0002931",
            amount=2500000.0,
            currency="INR",
            payment_channel="RTGS",
            transaction_status="SUCCESS",
            large_transfer=True,
            mule_account=True,
            blacklisted_account=True,
            relationship_keys={
                "account_beneficiary": "ACC-9911:::ACC-MULE-882",
                "customer_account": "CUST-A:::ACC-9911"
            },
            identity_chain=["customer:CUST-A"],
            asset_chain=[],
            transaction_chain=["account:ACC-9911", "beneficiary:ACC-MULE-882"]
        )
    },
    "IMPS": {
        "summary": "IMPS Instant Enriched Event",
        "value": _base_response(
            REQUEST_EXAMPLES["IMPS"]["value"],
            normalized_event_data={
                "transaction_id": "IMPS-90182",
                "amount": 15000.0,
                "sender_account": "ACC-9911",
                "receiver_account": "ACC-BOB-02",
                "receiver_bank": "ICICI Bank",
                "ifsc": "ICIC0001092"
            },
            customer_id="CUST-A",
            account_number="ACC-9911",
            sender_account="ACC-9911",
            receiver_account="ACC-BOB-02",
            receiver_bank="ICICI Bank",
            ifsc="ICIC0001092",
            amount=15000.0,
            currency="INR",
            payment_channel="IMPS",
            transaction_status="SUCCESS",
            relationship_keys={"customer_account": "CUST-A:::ACC-9911"},
            identity_chain=["customer:CUST-A"],
            asset_chain=[],
            transaction_chain=["account:ACC-9911", "beneficiary:ACC-BOB-02"]
        )
    },
    "Card": {
        "summary": "Card POS Transaction Enriched Event",
        "value": _base_response(
            REQUEST_EXAMPLES["Card"]["value"],
            normalized_event_data={
                "transaction_id": "TXN_77261",
                "card_number_masked": "411111XXXXXX1111",
                "amount": 25000.0,
                "merchant": "evil-gambling.com",
                "mcc": "5411"
            },
            customer_id="CUST-A",
            account_number="ACC-9911",
            sender_account="ACC-9911",
            card_number_masked="411111XXXXXX1111",
            merchant="evil-gambling.com",
            amount=25000.0,
            currency="INR",
            payment_channel="CARD",
            transaction_status="SUCCESS",
            pos_terminal="POS-TERM-MOSCOW-01",
            country="Russia",
            city="Moscow",
            region="Moscow",
            latitude=55.7558,
            longitude=37.6173,
            risky_merchant=True,
            high_risk_country=True,
            is_gps=True,
            relationship_keys={"customer_account": "CUST-A:::ACC-9911"},
            identity_chain=["customer:CUST-A"],
            asset_chain=[],
            transaction_chain=["account:ACC-9911"]
        )
    },
    "ATM": {
        "summary": "ATM Cash Withdrawal Enriched Event",
        "value": _base_response(
            REQUEST_EXAMPLES["ATM"]["value"],
            normalized_event_data={
                "transaction_id": "TXN-904",
                "atm_id": "ATM-BLR-04",
                "amount": 10000.0,
                "account_balance": None
            },
            customer_id="CUST-A",
            account_number="ACC-9911",
            sender_account="ACC-9911",
            card_number_masked="411111XXXXXX1111",
            amount=10000.0,
            currency="INR",
            payment_channel="ATM",
            transaction_status="SUCCESS",
            atm_id="ATM-BLR-04",
            country="India",
            city="Bengaluru MG Road",
            region="Karnataka",
            latitude=12.9716,
            longitude=77.5946,
            is_gps=True,
            relationship_keys={"customer_account": "CUST-A:::ACC-9911"},
            identity_chain=["customer:CUST-A"],
            asset_chain=["atm:ATM-BLR-04"],
            transaction_chain=["account:ACC-9911"]
        )
    },
    "Beneficiary": {
        "summary": "Beneficiary Configuration Enriched Event",
        "value": _base_response(
            REQUEST_EXAMPLES["Beneficiary"]["value"],
            normalized_event_data={
                "beneficiary_id": "BEN-BOB",
                "beneficiary_name": "Bob Smith",
                "beneficiary_account": "ACC-BOB-02",
                "operation_type": "ADD"
            },
            customer_id="CUST-A",
            account_number="ACC-9911",
            beneficiary_id="BEN-BOB",
            relationship_keys={"account_beneficiary": "ACC-9911:::BEN-BOB"},
            identity_chain=["customer:CUST-A"],
            asset_chain=[],
            transaction_chain=["account:ACC-9911", "beneficiary:BEN-BOB"]
        )
    },
    "EDR": {
        "summary": "EDR Endpoint Alert Enriched Event",
        "value": _base_response(
            REQUEST_EXAMPLES["EDR"]["value"],
            normalized_event_data={
                "hostname": "EMP-LAPTOP-102",
                "process_name": "powershell.exe",
                "process_hash": "44d88612fe583ed3d8151c5f139469a37e974e497920fe1e5c02450d03251d56",
                "malware_name": "WannaCry.ProcessInjection",
                "detection_status": "BLOCKED"
            },
            employee_id="EMP-908",
            device_type="Endpoint",
            cpu_usage=95.0,
            memory_usage=91.0,
            malware_name="WannaCry.ProcessInjection",
            process_name="powershell.exe",
            process_hash="44d88612fe583ed3d8151c5f139469a37e974e497920fe1e5c02450d03251d56",
            detection_status="BLOCKED",
            rule_id="sensor-cs-corp-laptop",
            mitre_tactic="Defense Evasion",
            mitre_technique="Process Injection",
            mitre_technique_id="T1055",
            abnormal_cpu_usage=True,
            abnormal_memory_usage=True,
            relationship_keys={"endpoint_process": "None:::44d88612fe583ed3d8151c5f139469a37e974e497920fe1e5c02450d03251d56"},
            identity_chain=["employee:EMP-908"],
            asset_chain=[]
        )
    },
    "SIEM": {
        "summary": "SIEM Aggregated Alert Enriched Event",
        "value": _base_response(
            REQUEST_EXAMPLES["SIEM"]["value"],
            normalized_event_data={
                "correlation_rule_name": "Excessive Failed Logins From Tor Exit Node",
                "correlation_rule_id": "rule-excessive-logins-tor",
                "attack_category": "Initial Access",
                "source_ip": "185.220.101.5",
                "destination_ip": "10.0.1.5"
            },
            employee_id="EMP-908",
            device_type="SIEM",
            ioc_match=True,
            ioc_value="185.220.101.5",
            ioc_type="IP_ADDRESS",
            ioc_confidence=0.95,
            malicious_ip="185.220.101.5",
            threat_actor="APT28",
            mitre_tactic="Initial Access",
            mitre_technique="External Remote Services",
            mitre_technique_id="T1133",
            relationship_keys={},
            identity_chain=["employee:EMP-908", "ip:185.220.101.5"],
            asset_chain=[]
        )
    },
    "ThreatFeed": {
        "summary": "Threat Intel Feed OSINT Enriched Event",
        "value": _base_response(
            REQUEST_EXAMPLES["ThreatFeed"]["value"],
            normalized_event_data={
                "ioc_value": "45.9.148.15",
                "ioc_type": "IP_ADDRESS",
                "threat_actor": "Wizard Spider",
                "campaign": "Ryuk Ransomware",
                "confidence": 0.95
            },
            device_type="Threat Intelligence Engine",
            ioc_match=True,
            ioc_value="45.9.148.15",
            ioc_type="IP_ADDRESS",
            ioc_confidence=0.95,
            malicious_ip="45.9.148.15",
            threat_actor="Wizard Spider",
            malware_family="Ryuk",
            attack_campaign="Ryuk Ransomware",
            mitre_tactic="Command and Control",
            mitre_technique="Application Layer Protocol",
            mitre_technique_id="T1071",
            relationship_keys={},
            identity_chain=["ip:45.9.148.15"],
            asset_chain=[]
        )
    },
    "Quantum": {
        "summary": "Quantum Crypto Audit Enriched Event",
        "value": _base_response(
            REQUEST_EXAMPLES["Quantum"]["value"],
            normalized_event_data={
                "anomaly_type": "HNDL_suspected",
                "crypto_algorithm": "Kyber768",
                "transfer_size_bytes": 5368709120,
                "transfer_time_ms": 150.5
            },
            employee_id="EMP-908",
            device_type="Quantum Sensor",
            encryption_status="Kyber768",
            large_archive_access=True,
            mitre_tactic="Exfiltration",
            mitre_technique="Exfiltration Over Alternative Protocol",
            mitre_technique_id="T1048",
            relationship_keys={},
            identity_chain=["employee:EMP-908", "ip:192.168.1.45"],
            asset_chain=[]
        )
    }
}
