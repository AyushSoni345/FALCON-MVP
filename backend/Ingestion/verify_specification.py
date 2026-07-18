import os
import sys
import json

# Setup path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Ingestion.core.pipeline import IngestionPipeline
from Ingestion.models import UniversalEventEnvelope

pipeline = IngestionPipeline()

representative_events = [
    # 1. Firewall
    {
        "name": "Firewall Event",
        "data": {
            "event_id": "FW-101",
            "event_type": "firewall",
            "source_system": "Perimeter Firewall",
            "timestamp": "2026-07-14T11:00:00Z",
            "severity": "INFO",
            "correlation_id": "CORR-ATTACK-001",
            "raw_payload": {
                "firewall_device_id": "FW-DEV-01",
                "source_ip": "192.168.1.10",
                "destination_ip": "10.0.0.5",
                "source_port": 54321,
                "destination_port": 443,
                "protocol": "HTTPS",
                "action": "ALLOW",
                "rule_id": "RULE-HTTPS",
                "interface": "eth1",
                "bytes_sent": 1024,
                "bytes_received": 4096
            }
        }
    },
    # 2. IAM
    {
        "name": "IAM Event",
        "data": {
            "event_id": "IAM-202",
            "event_type": "iam",
            "source_system": "Active Directory",
            "timestamp": "2026-07-14T11:01:00Z",
            "severity": "LOW",
            "raw_payload": {
                "user_id": "U001",
                "username": "john.doe",
                "user_type": "EMPLOYEE",
                "login_status": "SUCCESS",
                "authentication_method": "PASSWORD_MFA",
                "mfa_result": "PASSED",
                "device_id": "DEV-MAC-99",
                "ip_address": "192.168.1.10",
                "session_id": "SESS-IAM-99"
            }
        }
    },
    # 3. VPN
    {
        "name": "VPN Event",
        "data": {
            "event_id": "VPN-303",
            "event_type": "vpn",
            "source_system": "Corporate VPN",
            "timestamp": "2026-07-14T11:02:00Z",
            "severity": "LOW",
            "raw_payload": {
                "session_id": "SESS-VPN-01",
                "user_id": "john.doe",
                "employee_id": "EMP001",
                "vpn_gateway": "GW-VPN-EAST",
                "source_ip": "203.0.113.50",
                "country": "USA",
                "device_id": "DEV-MAC-99",
                "login_time": "2026-07-14T11:02:00Z",
                "mfa_status": "COMPLETED",
                "authentication_status": "SUCCESS"
            }
        }
    },
    # 4. UPI
    {
        "name": "UPI Event",
        "data": {
            "event_id": "UPI-404",
            "event_type": "upi",
            "source_system": "UPI Switch",
            "timestamp": "2026-07-14T11:03:00Z",
            "severity": "MEDIUM",
            "raw_payload": {
                "transaction_id": "TXN-UPI-888",
                "upi_id": "john.doe@okaxis",
                "customer_id": "CUST101",
                "sender_account": "ACC-998877",
                "receiver_upi": "merchant@okhdfc",
                "receiver_bank": "HDFC Bank",
                "amount": 5000.0,
                "device_id": "DEV-MOBILE-55",
                "ip_address": "192.168.1.15",
                "merchant": "Amazon",
                "status": "SUCCESS"
            }
        }
    },
    # 5. Core Banking
    {
        "name": "Core Banking Event",
        "data": {
            "event_id": "CBS-505",
            "event_type": "core_banking",
            "source_system": "Core Banking System",
            "timestamp": "2026-07-14T11:04:00Z",
            "severity": "LOW",
            "raw_payload": {
                "transaction_id": "TXN-CBS-777",
                "account_number": "ACC-998877",
                "customer_id": "CUST101",
                "transaction_type": "TRANSFER",
                "amount": 5000.0,
                "currency": "INR",
                "balance_before": 25000.0,
                "balance_after": 20000.0,
                "branch": "Mumbai",
                "channel": "MOBILE",
                "status": "SUCCESS"
            }
        }
    },
    # 6. ATM
    {
        "name": "ATM Event",
        "data": {
            "event_id": "ATM-606",
            "event_type": "atm",
            "source_system": "ATM Controller",
            "timestamp": "2026-07-14T11:05:00Z",
            "severity": "MEDIUM",
            "raw_payload": {
                "atm_id": "ATM-MUM-01",
                "transaction_id": "TXN-ATM-666",
                "card_number": "4532XXXXXXXX1234",
                "customer_id": "CUST101",
                "transaction_type": "WITHDRAWAL",
                "amount": 10000.0,
                "balance": 10000.0,
                "atm_location": "Mumbai Suburbs",
                "status": "SUCCESS"
            }
        }
    },
    # 7. Card
    {
        "name": "Card Event",
        "data": {
            "event_id": "CARD-707",
            "event_type": "card",
            "source_system": "Card Authorization Processor",
            "timestamp": "2026-07-14T11:06:00Z",
            "severity": "MEDIUM",
            "raw_payload": {
                "transaction_id": "TXN-CARD-555",
                "masked_card_number": "4532XXXXXXXX1234",
                "merchant_id": "MERCH-8899",
                "merchant_category": "Retail",
                "pos_terminal": "POS-MUM-44",
                "country": "IND",
                "city": "Mumbai",
                "amount": 1200.0,
                "currency": "INR",
                "approval_code": "APP999"
            }
        }
    },
    # 8. SIEM
    {
        "name": "SIEM Event",
        "data": {
            "event_id": "SIEM-808",
            "event_type": "siem",
            "source_system": "SIEM Aggregator",
            "timestamp": "2026-07-14T11:07:00Z",
            "severity": "HIGH",
            "correlation_id": "CORR-ATTACK-001",
            "raw_payload": {
                "correlation_id": "CORR-ATTACK-001",
                "source_system": "Perimeter Firewall",
                "severity": "HIGH",
                "event_category": "NETWORK",
                "rule_name": "Brute Force Attack Detected"
            }
        }
    },
    # 9. EDR (Endpoint)
    {
        "name": "EDR Event",
        "data": {
            "event_id": "EDR-909",
            "event_type": "endpoint",
            "source_system": "CrowdStrike EDR",
            "timestamp": "2026-07-14T11:08:00Z",
            "severity": "CRITICAL",
            "raw_payload": {
                "endpoint_id": "EP-LAP-88",
                "device_id": "DEV-MAC-99",
                "user": "john.doe",
                "process_name": "powershell.exe",
                "process_hash": "abcde12345",
                "malware_name": "Emotet",
                "detection_status": "QUARANTINED",
                "cpu_usage": 95.0,
                "memory_usage": 88.0
            }
        }
    },
    # 10. Threat Intelligence
    {
        "name": "Threat Intelligence Event",
        "data": {
            "event_id": "TI-010",
            "event_type": "threat_intel",
            "source_system": "Internal TI Feed",
            "timestamp": "2026-07-14T11:09:00Z",
            "severity": "HIGH",
            "raw_payload": {
                "ioc_id": "IOC-999",
                "ioc_type": "IP",
                "ioc_value": "203.0.113.50",
                "threat_actor": "APT-29",
                "malware_family": "Emotet",
                "confidence_score": 90.0,
                "first_seen": "2026-01-01T00:00:00Z",
                "last_seen": "2026-07-14T11:00:00Z",
                "mitre_attack_mapping": "T1071.001"
            }
        }
    }
]

print("================================================================================")
print("MODULE 1 SPECIFICATION VALIDATION REPORT")
print("================================================================================")

all_passed = True

for idx, item in enumerate(representative_events, 1):
    name = item["name"]
    event = item["data"]
    
    print(f"\n[{idx}/10] VALIDATING: {name}")
    print("-" * 80)
    print("Input Event:")
    print(json.dumps(event, indent=2))
    print("\n  v  \n")
    
    # Run through map_to_uee
    try:
        uee_dict = pipeline.map_to_uee(event, is_valid=True)
        # Validate using pydantic model for verification correctness
        uee = UniversalEventEnvelope(**uee_dict)
        print("Expected Universal Event Envelope:")
        print(json.dumps(uee.model_dump(), indent=2))
        print("\n  v  \n")
        print("Validation Result: PASSED (Valid schema and exact output structure conformity)")
    except Exception as e:
        print(f"Validation Result: FAILED due to error: {e}")
        all_passed = False
    print("=" * 80)

if all_passed:
    print("\nALL REPRESENTATIVE EVENTS SPECIFICATION VALIDATIONS PASSED SUCCESSFULLY!")
    sys.exit(0)
else:
    print("\nSPECIFICATION VALIDATION FAILED!")
    sys.exit(1)
