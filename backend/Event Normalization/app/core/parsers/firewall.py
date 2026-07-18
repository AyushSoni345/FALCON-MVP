from typing import Dict, Any
from app.core.parsers.base import BaseParser, get_case_insensitive, normalize_severity
from app.core.schema import UniversalEventEnvelope

class FirewallParser(BaseParser):
    """Parses network firewall events (Cisco, Fortinet, Palo Alto etc.)."""

    def validate(self, uee: UniversalEventEnvelope) -> bool:
        rp = uee.raw_payload or {}
        src_ip = uee.network_context.source_ip or get_case_insensitive(rp, ["SRC_IP", "src_ip", "source_ip"])
        return src_ip is not None

    def normalize(self, uee: UniversalEventEnvelope) -> Dict[str, Any]:
        nc = uee.network_context
        sc = uee.security_context
        rp = uee.raw_payload or {}

        identity = self.extract_identity(uee)
        asset = self.extract_assets(uee)
        
        asset["device_type"] = "Firewall"
        asset["firewall"] = sc.firewall_device or get_case_insensitive(rp, ["firewall_device", "fw", "device"])

        src_ip = nc.source_ip or get_case_insensitive(rp, ["SRC_IP", "src_ip", "source_ip", "Client_IP"])
        dst_ip = nc.destination_ip or get_case_insensitive(rp, ["DST_IP", "dst_ip", "destination_ip"])
        sport = nc.source_port or get_case_insensitive(rp, ["SOURCE_PORT", "src_port", "source_port", "sport"])
        dport = nc.destination_port or get_case_insensitive(rp, ["DESTINATION_PORT", "dst_port", "destination_port", "dport"])
        protocol = nc.protocol or get_case_insensitive(rp, ["PROTOCOL", "proto", "protocol"])
        bytes_sent = get_case_insensitive(rp, ["BYTES_SENT", "bytes_sent", "sent_bytes"])
        bytes_received = get_case_insensitive(rp, ["BYTES_RECEIVED", "bytes_received", "recv_bytes"])

        network = {
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "public_ip": nc.public_ip,
            "source_port": int(sport) if sport and str(sport).isdigit() else None,
            "destination_port": int(dport) if dport and str(dport).isdigit() else None,
            "protocol": str(protocol).upper() if protocol else None,
            "country": nc.country,
            "city": nc.city,
            "network_zone": get_case_insensitive(rp, ["network_zone", "zone"]) or "Internal",
            "vpn_used": False,
            "proxy_used": False,
            "connection_type": get_case_insensitive(rp, ["connection_type", "type"])
        }

        identity["ip_address"] = src_ip

        severity = sc.severity or get_case_insensitive(rp, ["severity", "level"])
        action = sc.action or get_case_insensitive(rp, ["ACTION", "action"])
        rule_id = sc.rule_id or get_case_insensitive(rp, ["RULE_ID", "rule_id", "rule"])

        security = {
            "severity": normalize_severity(severity),
            "action": str(action).upper() if action else None,
            "rule_id": str(rule_id) if rule_id else None,
            "sensor_id": sc.sensor_id,
            "log_source": sc.log_source or "Firewall",
        }

        normalized_data = {
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "source_port": network["source_port"],
            "destination_port": network["destination_port"],
            "protocol": network["protocol"],
            "action": security["action"],
            "rule_id": security["rule_id"],
            "bytes_sent": int(bytes_sent) if bytes_sent and str(bytes_sent).isdigit() else None,
            "bytes_received": int(bytes_received) if bytes_received and str(bytes_received).isdigit() else None
        }

        return {
            "identity_context": identity,
            "asset_context": asset,
            "network_context": network,
            "financial_context": {},
            "security_context": security,
            "normalized_event_data": normalized_data
        }
