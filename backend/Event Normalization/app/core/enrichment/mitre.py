import logging
from typing import Dict, Any
from app.core.enrichment.base import BaseEnricher
from app.logging_config import log_pipeline

class MitreMapper(BaseEnricher):
    """Maps normalized security events and transaction behaviors to MITRE ATT&CK TTPs."""

    def enrich(self, event: Dict[str, Any]) -> Dict[str, Any]:
        tc = event.get("threat_context", {})
        sec = event.get("security_context", {})
        info = event.get("event_information", {})
        raw = event.get("raw_payload", {})

        event_uuid = info.get("event_uuid")
        corr_id = info.get("correlation_id")

        log_pipeline(
            logging.DEBUG,
            "Mapping event patterns to MITRE ATT&CK database.",
            "mitre_mapping",
            "started",
            event_uuid=event_uuid,
            correlation_id=corr_id
        )

        event_type = info.get("event_type", "").upper()
        source_system = info.get("source_system", "").upper()
        
        proc_name = str(sec.get("process_name", "")).lower()
        desc_lower = str(raw.get("description", raw.get("event_description", ""))).lower()

        tactic = None
        technique = None
        tech_id = None

        if "QUANTUM" in event_type or raw.get("anomaly_type") == "HNDL_suspected" or "hndl" in desc_lower:
            tactic = "Exfiltration"
            technique = "Exfiltration Over Alternative Protocol"
            tech_id = "T1048"
        elif "EDR" in source_system or "EDR" in event_type:
            if "inject" in desc_lower or "injection" in desc_lower or "inject" in proc_name:
                tactic = "Defense Evasion"
                technique = "Process Injection"
                tech_id = "T1055"
            elif "lsass" in desc_lower or "dump" in desc_lower:
                tactic = "Credential Access"
                technique = "OS Credential Dumping"
                tech_id = "T1003"
            else:
                tactic = "Execution"
                technique = "User Execution"
                tech_id = "T1204"
        elif tc.get("IOC_match") and tc.get("IOC_type") == "IP_ADDRESS" and tc.get("malicious_ip") == "45.9.148.15":
            tactic = "Command and Control"
            technique = "Application Layer Protocol"
            tech_id = "T1071"
        elif "VPN" in event_type or (tc.get("IOC_match") and tc.get("IOC_type") == "IP_ADDRESS" and tc.get("malicious_ip") == "185.220.101.5"):
            tactic = "Initial Access"
            technique = "External Remote Services"
            tech_id = "T1133"
        elif "IAM" in event_type or "ACTIVE_DIRECTORY" in source_system:
            if "fail" in desc_lower or "brute" in desc_lower or "lockout" in desc_lower:
                tactic = "Credential Access"
                technique = "Brute Force"
                tech_id = "T1110"
            else:
                tactic = "Credential Access"
                technique = "Valid Accounts"
                tech_id = "T1078"
        elif event.get("fraud_context", {}).get("large_transfer") and event.get("fraud_context", {}).get("first_time_payee"):
            tactic = "Impact"
            technique = "Financial Manipulation"
            tech_id = "T1565.001"

        if tactic and technique and tech_id:
            tc.update({
                "MITRE_tactic": tactic,
                "MITRE_technique": technique,
                "MITRE_technique_id": tech_id
            })
            event["threat_context"] = tc
            log_pipeline(
                logging.DEBUG,
                f"Pattern mapped to MITRE: Tactic={tactic}, TechID={tech_id}",
                "mitre_mapping",
                "success",
                event_uuid=event_uuid,
                correlation_id=corr_id
            )
        else:
            log_pipeline(
                logging.DEBUG,
                "No mapping matching MITRE ATT&CK criteria.",
                "mitre_mapping",
                "success",
                event_uuid=event_uuid,
                correlation_id=corr_id
            )

        return event
