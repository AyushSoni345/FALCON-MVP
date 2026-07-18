from typing import Dict, Any
from app.core.parsers.base import BaseParser, get_case_insensitive, normalize_severity
from app.core.schema import UniversalEventEnvelope

class SIEMParser(BaseParser):
    """Parses aggregated security information correlation event logs (Splunk, QRadar, etc.)."""

    def normalize(self, uee: UniversalEventEnvelope) -> Dict[str, Any]:
        nc = uee.network_context
        sc = uee.security_context
        rp = uee.raw_payload or {}

        identity = self.extract_identity(uee)
        asset = self.extract_assets(uee)

        corr_id = get_case_insensitive(rp, ["Correlation_ID", "correlation_id", "rule_id"])
        rule_name = get_case_insensitive(rp, ["Correlation_Rule_Name", "rule_name", "signature"])
        att_name = get_case_insensitive(rp, ["Attack_Category", "attack_name", "category"])

        src_ip = nc.source_ip or get_case_insensitive(rp, ["Source_IP", "src_ip", "source_ip"])
        dst_ip = nc.destination_ip or get_case_insensitive(rp, ["Destination_IP", "dst_ip", "destination_ip"])
        identity["ip_address"] = src_ip

        network = {
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "public_ip": nc.public_ip or src_ip,
            "source_port": nc.source_port,
            "destination_port": nc.destination_port,
            "protocol": nc.protocol,
            "country": nc.country,
            "city": nc.city,
            "network_zone": "DMZ",
        }

        severity = sc.severity or get_case_insensitive(rp, ["Severity", "severity", "level"])
        action = sc.action or get_case_insensitive(rp, ["Action", "action"])

        security = {
            "severity": normalize_severity(severity),
            "action": str(action).upper() if action else None,
            "rule_name": str(rule_name) if rule_name else None,
            "rule_id": str(corr_id) if corr_id else sc.rule_id,
            "attack_name": str(att_name) if att_name else None,
            "sensor_id": sc.sensor_id,
            "log_source": sc.log_source or "SIEM",
        }

        normalized_data = {
            "correlation_rule_name": security["rule_name"],
            "correlation_rule_id": security["rule_id"],
            "attack_category": security["attack_name"],
            "source_ip": src_ip,
            "destination_ip": dst_ip
        }

        return {
            "identity_context": identity,
            "asset_context": asset,
            "network_context": network,
            "financial_context": {},
            "security_context": security,
            "normalized_event_data": normalized_data
        }
