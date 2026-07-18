import logging
from datetime import datetime, timezone
from typing import Dict, Any
from app.core.enrichment.base import BaseEnricher
from app.logging_config import log_pipeline

# Static database configs
MALICIOUS_IPS = {
    "185.220.101.5": {"reason": "Known Tor Exit Node used for anonymous scanning", "actor": "APT28", "campaign": "Operation Cobalt"},
    "45.9.148.15": {"reason": "Active C2 callback server", "actor": "Wizard Spider", "campaign": "Ryuk Ransomware"},
    "198.51.100.42": {"reason": "Hosting credential harvesting panel", "actor": "Cozy Bear", "campaign": "Phish-Storm"},
}

MALICIOUS_DOMAINS = {
    "secure-falcon-login.com": {"reason": "Credential harvesting phishing site", "actor": "UNC115", "campaign": "FALCON-Harvest"},
    "c2-malware-callback.net": {"reason": "C2 heartbeat server", "actor": "Wizard Spider", "campaign": "Ryuk Ransomware"},
    "eviltracker-update.ru": {"reason": "Malware dropper domain", "actor": "Fancy Bear", "campaign": "Dropper-Campaign"},
}

MALWARE_HASHES = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {"reason": "EICAR standard AV signature test", "family": "TestAV"},
    "44d88612fe583ed3d8151c5f139469a37e974e497920fe1e5c02450d03251d56": {"reason": "WannaCry Ransomware binary payload", "family": "WannaCry"},
}

RISKY_ASNS = {"AS20473", "AS60924"}

class ThreatIntelEnricher(BaseEnricher):
    """Enriches event telemetry against Indicators of Compromise (IOCs) and malware registries."""

    def enrich(self, event: Dict[str, Any]) -> Dict[str, Any]:
        tc = event.get("threat_context", {})
        net = event.get("network_context", {})
        ident = event.get("identity_context", {})
        sec = event.get("security_context", {})
        raw = event.get("raw_event", event.get("raw_payload", {}))
        info = event.get("event_information", {})

        event_uuid = info.get("event_uuid")
        corr_id = info.get("correlation_id")

        log_pipeline(
            logging.DEBUG,
            "Querying threat intelligence database for indicators.",
            "threat_enrichment",
            "started",
            event_uuid=event_uuid,
            correlation_id=corr_id
        )

        now_str = datetime.utcnow().replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        # Initialize defaults
        ioc_match = False
        ioc_value = None
        ioc_type = None
        confidence = 0.0
        actor = None
        campaign = None
        family = None
        mal_ip = None
        mal_domain = None
        mal_hash = None
        reason = "No threat indicators matched."

        # 1. Evaluate Source IP
        src_ip = net.get("source_ip") or ident.get("ip_address")
        if src_ip and src_ip in MALICIOUS_IPS:
            ioc_match = True
            ioc_value = src_ip
            ioc_type = "IP_ADDRESS"
            confidence = 0.95
            actor = MALICIOUS_IPS[src_ip]["actor"]
            campaign = MALICIOUS_IPS[src_ip]["campaign"]
            mal_ip = src_ip
            reason = MALICIOUS_IPS[src_ip]["reason"]

        # 2. Evaluate Destination IP
        dst_ip = net.get("destination_ip")
        if not ioc_match and dst_ip and dst_ip in MALICIOUS_IPS:
            ioc_match = True
            ioc_value = dst_ip
            ioc_type = "IP_ADDRESS"
            confidence = 0.85
            actor = MALICIOUS_IPS[dst_ip]["actor"]
            campaign = MALICIOUS_IPS[dst_ip]["campaign"]
            mal_ip = dst_ip
            reason = MALICIOUS_IPS[dst_ip]["reason"]

        # 3. Evaluate Domains
        domain_keys = ["domain", "domain_name", "host", "hostname", "destination_host", "url", "phishing_domain"]
        if not ioc_match:
            for dk in domain_keys:
                raw_val = raw.get(dk)
                if raw_val and isinstance(raw_val, str):
                    for mal_dom, data in MALICIOUS_DOMAINS.items():
                        if mal_dom in raw_val.lower():
                            ioc_match = True
                            ioc_value = raw_val
                            ioc_type = "DOMAIN"
                            confidence = 0.98
                            actor = data["actor"]
                            campaign = data["campaign"]
                            mal_domain = mal_dom
                            reason = data["reason"]
                            break
                if ioc_match:
                    break

        # 4. Evaluate File/Process Hash
        hash_keys = ["process_hash", "file_hash", "hash", "md5", "sha256"]
        if not ioc_match:
            for hk in hash_keys:
                raw_hash = sec.get(hk) or raw.get(hk)
                if raw_hash and isinstance(raw_hash, str):
                    clean_hash = raw_hash.strip().lower()
                    if clean_hash in MALWARE_HASHES:
                        ioc_match = True
                        ioc_value = raw_hash
                        ioc_type = "HASH"
                        confidence = 1.0
                        family = MALWARE_HASHES[clean_hash]["family"]
                        mal_hash = clean_hash
                        reason = MALWARE_HASHES[clean_hash]["reason"]
                        break
            
            mal_name = sec.get("malware_name") or raw.get("malware_name")
            if not ioc_match and mal_name:
                ioc_match = True
                ioc_value = mal_name
                ioc_type = "MALWARE_NAME"
                confidence = 0.90
                reason = f"Security agent flagged threat: {mal_name}"

        # 5. Populate threat_context
        tc.update({
            "IOC_match": ioc_match,
            "IOC_value": ioc_value,
            "IOC_type": ioc_type,
            "IOC_confidence": confidence,
            "malicious_ip": mal_ip,
            "malicious_domain": mal_domain,
            "malicious_hash": mal_hash,
            "threat_actor": actor,
            "malware_family": family,
            "ATTACK_campaign": campaign,
            "reputation_score": confidence * 10.0,
            "intel_source": "FALCON_Threat_Intel_Feeds",
            "intel_timestamp": now_str
        })

        event["threat_context"] = tc

        if ioc_match:
            event["security_context"]["severity"] = "HIGH"
            log_pipeline(
                logging.WARNING,
                f"Threat indicator matched: Type={ioc_type}, Value={ioc_value}, Reason={reason}",
                "threat_enrichment",
                "success",
                event_uuid=event_uuid,
                correlation_id=corr_id
            )
        else:
            log_pipeline(
                logging.DEBUG,
                "Threat intelligence lookup finished with zero matches.",
                "threat_enrichment",
                "success",
                event_uuid=event_uuid,
                correlation_id=corr_id
            )
            
        return event
