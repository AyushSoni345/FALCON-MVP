import os
import json
import threading
import uuid
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, Tuple, Optional

from Ingestion import config
from Ingestion.config import MAX_SEEN_CACHE
from Ingestion.core.validator import validate_event
from Ingestion.core.deduplicator import Deduplicator
from Ingestion.core.chronology import ChronologyManager
from Ingestion.models import (
    UniversalEventEnvelope, 
    UEE_Metadata, 
    UEE_EntityContext, 
    UEE_NetworkContext, 
    UEE_SecurityContext
)

class IngestionPipeline:
    def __init__(self):
        self.deduplicator = Deduplicator(max_cache_size=MAX_SEEN_CACHE)
        self.chronology = ChronologyManager()
        self.write_lock = threading.Lock()
        self.original_id_to_uuid = {}
        self._restored = False
        self._lock = threading.Lock()

    def restore_state_if_needed(self):
        """Scans the output NDJSON file to rebuild deduplicator and chronology caches."""
        with self._lock:
            if self._restored:
                return
            
            if not os.path.exists(config.OUTPUT_PATH):
                self._restored = True
                return
                
            print(f"[*] Restoring state from existing stream: {config.OUTPUT_PATH}")
            event_ids = []
            
            try:
                with open(config.OUTPUT_PATH, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            ev = json.loads(line)
                            # Check if UEE format
                            if "metadata" in ev and "entity_context" in ev:
                                ev_id = ev["metadata"].get("original_event_id")
                                if ev_id:
                                    event_ids.append(ev_id)
                                    
                                ts = ev["metadata"].get("original_timestamp")
                                sess_id = ev["entity_context"].get("session_id")
                                corr_id = ev["metadata"].get("correlation_id")
                                if ts:
                                    self.chronology.load_historical_record(ts, sess_id, corr_id)
                                    
                                # Track event_uuid for duplicate references
                                ev_uuid = ev["metadata"].get("event_uuid")
                                if ev_id and ev_uuid:
                                    self.original_id_to_uuid[ev_id] = ev_uuid
                            else:
                                # Fallback to old format
                                ev_id = ev.get("event_id")
                                if ev_id:
                                    event_ids.append(ev_id)
                                ts = ev.get("timestamp")
                                sess_id = ev.get("session_id")
                                corr_id = ev.get("correlation_id")
                                if ts:
                                    self.chronology.load_historical_record(ts, sess_id, corr_id)
                        except Exception:
                            # Skip broken lines in historical recovery
                            continue
            except Exception as e:
                print(f"[!] Warning: Failed to restore state from file: {e}")
                
            self.deduplicator.load_from_list(event_ids)
            self._restored = True
            print(f"[*] State restored: Loaded {len(event_ids)} event IDs into deduplication cache.")

    def map_to_uee(
        self, 
        event_dict: Dict[str, Any], 
        is_valid: bool, 
        err_msg: Optional[str] = None, 
        is_duplicate: bool = False, 
        original_uuid: Optional[str] = None
    ) -> Dict[str, Any]:
        # Compute event hash
        event_str = json.dumps(event_dict, sort_keys=True)
        event_hash = hashlib.sha256(event_str.encode('utf-8')).hexdigest()
        
        payload_dict = event_dict.get("raw_payload", {})
        
        def extract_field(keys: list) -> Optional[Any]:
            for key in keys:
                if key in event_dict and event_dict[key] is not None:
                    return event_dict[key]
                if key in payload_dict and payload_dict[key] is not None:
                    return payload_dict[key]
            return None

        etype = str(event_dict.get("event_type", "")).lower()
        category_map = {
            "firewall": "NETWORK",
            "ids_ips": "NETWORK",
            "vpn": "AUTHENTICATION",
            "iam": "AUTHENTICATION",
            "internet_banking": "AUTHENTICATION",
            "core_banking": "TRANSACTION",
            "upi": "PAYMENT",
            "neft_rtgs_imps": "PAYMENT",
            "card": "PAYMENT",
            "atm": "TRANSACTION",
            "beneficiary": "TRANSACTION",
            "endpoint": "ENDPOINT",
            "siem": "ENDPOINT",
            "threat_intel": "THREAT_INTEL",
            "quantum_hndl": "QUANTUM"
        }
        category = category_map.get(etype, "OTHER")
        
        vendor_map = {
            "firewall": "Palo Alto Networks",
            "ids_ips": "Snort",
            "vpn": "Cisco",
            "iam": "Okta",
            "internet_banking": "Internal Banking",
            "core_banking": "Internal Banking",
            "upi": "NPCI",
            "neft_rtgs_imps": "RBI",
            "card": "Visa",
            "atm": "Diebold Nixdorf",
            "beneficiary": "Internal Banking",
            "endpoint": "CrowdStrike",
            "siem": "Splunk",
            "threat_intel": "Anomali",
            "quantum_hndl": "Internal"
        }
        vendor = vendor_map.get(etype, "Simulator")

        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        ev_uuid = str(uuid.uuid4())
        
        metadata = UEE_Metadata(
            event_uuid=ev_uuid,
            original_event_id=str(event_dict.get("event_id", "")),
            event_type=etype.upper(),
            event_category=category,
            source_system=str(event_dict.get("source_system", "")),
            source_vendor=vendor,
            ingestion_timestamp=now_str,
            original_timestamp=str(event_dict.get("timestamp", "")),
            processing_timestamp=now_str,
            validation_status="VALID" if is_valid else "INVALID",
            validation_errors=err_msg,
            duplicate_status="DUPLICATE" if is_duplicate else "UNIQUE",
            duplicate_reference=original_uuid,
            processing_status="ACCEPTED" if (is_valid and not is_duplicate) else "REJECTED",
            schema_version="1.0.0",
            pipeline_version="1.0.0",
            event_hash=event_hash,
            correlation_id=event_dict.get("correlation_id"),
            batch_id=event_dict.get("batch_id"),
            stream_id=event_dict.get("stream_id"),
            event_size=len(event_str),
            event_priority=str(event_dict.get("severity", "INFO"))
        )
        
        entity_context = UEE_EntityContext(
            customer_id=extract_field(["customer_id"]),
            employee_id=extract_field(["employee_id"]),
            username=extract_field(["username", "user"]),
            account_number=extract_field(["account_number", "sender_account"]),
            card_number_masked=extract_field(["card_number_masked", "masked_card_number", "card_number"]),
            transaction_id=extract_field(["transaction_id"]),
            beneficiary_id=extract_field(["beneficiary_id", "beneficiary_account"]),
            device_id=extract_field(["device_id"]),
            endpoint_id=extract_field(["endpoint_id"]),
            session_id=extract_field(["session_id"]),
            user_id=extract_field(["user_id"])
        )
        
        network_context = UEE_NetworkContext(
            source_ip=extract_field(["source_ip", "ip_address"]),
            destination_ip=extract_field(["destination_ip"]),
            public_ip=extract_field(["public_ip"]),
            source_port=extract_field(["source_port"]),
            destination_port=extract_field(["destination_port"]),
            protocol=extract_field(["protocol"]),
            country=extract_field(["country"]),
            city=extract_field(["city"])
        )
        
        security_context = UEE_SecurityContext(
            severity=extract_field(["severity"]),
            action=extract_field(["action"]),
            log_source=extract_field(["log_source", "source_system"]),
            sensor_id=extract_field(["sensor_id"]),
            firewall_device=extract_field(["firewall_device", "firewall_device_id"]),
            rule_id=extract_field(["rule_id", "rule_name"]),
            signature_id=extract_field(["signature_id"])
        )
        
        uee = UniversalEventEnvelope(
            metadata=metadata,
            entity_context=entity_context,
            network_context=network_context,
            security_context=security_context,
            raw_payload=payload_dict
        )
        return uee.model_dump()

    def ingest_event(self, event_dict: Dict[str, Any]) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Runs the full ingestion pipeline: Schema check -> Deduplication -> Chronology -> Save.
        Returns (is_success, error_msg, success_response_payload).
        """
        # Ensure cache state is restored
        self.restore_state_if_needed()

        # Step 1: Validate Schema
        is_valid, err_msg, envelope = validate_event(event_dict)
        if not is_valid or not envelope:
            return False, err_msg, {}

        # Step 2: Deduplication Check
        if self.deduplicator.is_duplicate(envelope.event_id):
            return False, f"Duplicate event rejected: '{envelope.event_id}'", {}

        # Step 3: Chronology Check
        ok, chrono_err = self.chronology.check_and_update(
            timestamp_str=envelope.timestamp,
            session_id=envelope.session_id,
            correlation_id=envelope.correlation_id
        )
        if not ok:
            return False, chrono_err, {}

        # Construct UEE
        uee_dict = self.map_to_uee(event_dict, is_valid=True, err_msg=None, is_duplicate=False, original_uuid=None)

        # Step 4: Write to unified NDJSON log stream thread-safely
        event_json = json.dumps(uee_dict)
        try:
            with self.write_lock:
                # Ensure parent directories exist
                os.makedirs(os.path.dirname(config.OUTPUT_PATH), exist_ok=True)
                with open(config.OUTPUT_PATH, "a", encoding="utf-8") as f:
                    f.write(event_json + "\n")
                
                # Save event UUID for future duplicates
                self.original_id_to_uuid[envelope.event_id] = uee_dict["metadata"]["event_uuid"]
        except Exception as e:
            return False, f"Storage write failure: {e}", {}

        # Step 5: Construct Success Response
        ingested_at = uee_dict["metadata"]["ingestion_timestamp"]
        response = {
            "status": "accepted",
            "event_id": envelope.event_id,
            "ingested_at": ingested_at
        }
        return True, "", response

# Global single instance of IngestionPipeline
pipeline = IngestionPipeline()
