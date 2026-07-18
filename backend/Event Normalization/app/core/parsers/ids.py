from typing import Dict, Any
from app.core.parsers.base import BaseParser, get_case_insensitive, normalize_severity
from app.core.schema import UniversalEventEnvelope

class IDSParser(BaseParser):
    """Parses Intrusion Detection System (IDS/IPS) telemetry."""

    def normalize(self, uee: UniversalEventEnvelope) -> Dict[str, Any]:
        nc = uee.network_context
        sc = uee.security_context
        rp = uee.raw_payload or {}

        identity = self.extract_identity(uee)
        asset = self.extract_assets(uee)
        asset["device_type"] = "IDS"

        src_ip = nc.source_ip or get_case_insensitive(rp, ["Source_IP", "src_ip", "source_ip"])
        dst_ip = nc.destination_ip or get_case_insensitive(rp, ["Destination_IP", "dst_ip", "destination_ip"])
        sport = nc.source_port or get_case_insensitive(rp, ["SOURCE_PORT", "src_port", "source_port", "sport"])
        dport = nc.destination_port or get_case_insensitive(rp, ["DESTINATION_PORT", "dst_port", "destination_port", "dport"])
        protocol = nc.protocol or get_case_insensitive(rp, ["Protocol", "protocol", "proto"])

        network = {
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "public_ip": nc.public_ip,
            "source_port": int(sport) if sport and str(sport).isdigit() else None,
            "destination_port": int(dport) if dport and str(dport).isdigit() else None,
            "protocol": str(protocol).upper() if protocol else None,
            "country": nc.country,
            "city": nc.city,
            "network_zone": "DMZ",
        }

        identity["ip_address"] = src_ip

        severity = sc.severity or get_case_insensitive(rp, ["Severity", "severity", "level"])
        action = sc.action or get_case_insensitive(rp, ["Action", "action"])
        signature_id = sc.signature_id or get_case_insensitive(rp, ["Signature_ID", "signature_id", "sig_id"])
        attack_name = get_case_insensitive(rp, ["Attack_Name", "attack_name", "signature_name"])

        security = {
            "severity": normalize_severity(severity),
            "action": str(action).upper() if action else None,
            "signature": str(attack_name) if attack_name else None,
            "signature_id": str(signature_id) if signature_id else None,
            "attack_name": str(attack_name) if attack_name else None,
            "sensor_id": sc.sensor_id,
            "log_source": sc.log_source or "IDS",
        }

        normalized_data = {
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "source_port": network["source_port"],
            "destination_port": network["destination_port"],
            "protocol": network["protocol"],
            "signature_id": security["signature_id"],
            "attack_name": security["attack_name"]
        }

        return {
            "identity_context": identity,
            "asset_context": asset,
            "network_context": network,
            "financial_context": {},
            "security_context": security,
            "normalized_event_data": normalized_data
        }
