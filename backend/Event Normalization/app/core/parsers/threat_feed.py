from typing import Dict, Any
from app.core.parsers.base import BaseParser, get_case_insensitive, normalize_severity
from app.core.schema import UniversalEventEnvelope

class ThreatFeedParser(BaseParser):
    """Parses raw external Threat Intelligence Feed threat logs (OSINT, Anomali, etc.)."""

    def normalize(self, uee: UniversalEventEnvelope) -> Dict[str, Any]:
        nc = uee.network_context
        sc = uee.security_context
        rp = uee.raw_payload or {}

        identity = self.extract_identity(uee)
        asset = self.extract_assets(uee)

        ioc_val = get_case_insensitive(rp, ["IOC_Value", "ioc_val", "ioc_value", "ioc"])
        ioc_type = get_case_insensitive(rp, ["IOC_Type", "ioc_type", "type"])
        threat_actor = get_case_insensitive(rp, ["Threat_Actor", "threat_actor", "actor"])
        campaign = get_case_insensitive(rp, ["Campaign", "campaign"])
        mal_fam = get_case_insensitive(rp, ["Malware_Family", "malware_family", "family"])
        confidence_raw = get_case_insensitive(rp, ["Confidence", "confidence", "score"], 0.5)

        confidence = 0.5
        if confidence_raw is not None:
            try:
                confidence = float(confidence_raw)
                if confidence > 1.0:
                    # Normalized to 0.0 - 1.0
                    confidence = confidence / 100.0
            except ValueError:
                pass

        threat_info = {
            "IOC_match": True,
            "IOC_value": str(ioc_val) if ioc_val else None,
            "IOC_type": str(ioc_type).upper() if ioc_type else None,
            "IOC_confidence": confidence,
            "threat_actor": str(threat_actor) if threat_actor else None,
            "malware_family": str(mal_fam) if mal_fam else None,
            "ATTACK_campaign": str(campaign) if campaign else None,
            "reputation_score": confidence * 10.0,
            "intel_source": "OSINT_Threat_Feed"
        }

        # Handle IP indicator bindings
        src_ip = None
        if ioc_type and str(ioc_type).upper() == "IP_ADDRESS" and ioc_val:
            src_ip = str(ioc_val)
            threat_info["malicious_ip"] = src_ip
            identity["ip_address"] = src_ip
        elif ioc_type and str(ioc_type).upper() == "DOMAIN" and ioc_val:
            threat_info["malicious_domain"] = str(ioc_val)
        elif ioc_type and str(ioc_type).upper() == "HASH" and ioc_val:
            threat_info["malicious_hash"] = str(ioc_val)

        src_ip = src_ip or nc.source_ip or get_case_insensitive(rp, ["IP", "ip"])
        network = {
            "source_ip": src_ip,
            "destination_ip": nc.destination_ip,
            "public_ip": nc.public_ip or src_ip,
            "source_port": nc.source_port,
            "destination_port": nc.destination_port,
            "protocol": nc.protocol,
            "country": nc.country,
            "city": nc.city,
            "network_zone": "External",
        }

        severity = sc.severity or get_case_insensitive(rp, ["severity", "level"])
        action = sc.action or get_case_insensitive(rp, ["action", "status"])

        security = {
            "severity": normalize_severity(severity) if severity else "HIGH",
            "action": str(action).upper() if action else "ALERT",
            "log_source": sc.log_source or "ThreatFeed",
        }

        normalized_data = {
            "ioc_value": threat_info["IOC_value"],
            "ioc_type": threat_info["IOC_type"],
            "threat_actor": threat_info["threat_actor"],
            "campaign": threat_info["ATTACK_campaign"],
            "confidence": threat_info["IOC_confidence"]
        }

        return {
            "identity_context": identity,
            "asset_context": asset,
            "network_context": network,
            "financial_context": {},
            "security_context": security,
            "threat_context": threat_info,
            "normalized_event_data": normalized_data
        }
