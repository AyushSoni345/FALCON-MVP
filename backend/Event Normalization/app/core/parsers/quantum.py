from typing import Dict, Any
from app.core.parsers.base import BaseParser, get_case_insensitive, normalize_severity
from app.core.schema import UniversalEventEnvelope

class QuantumParser(BaseParser):
    """Parses Quantum Post-Quantum Cryptography network audit telemetry."""

    def normalize(self, uee: UniversalEventEnvelope) -> Dict[str, Any]:
        nc = uee.network_context
        sc = uee.security_context
        rp = uee.raw_payload or {}

        identity = self.extract_identity(uee)
        asset = self.extract_assets(uee)
        asset["device_type"] = "Quantum-Cryptographic Gateway"

        anom_type = get_case_insensitive(rp, ["Anomaly_Type", "anomaly_type", "anomaly"])
        cipher = get_case_insensitive(rp, ["Crypto_Algorithm", "crypto_algorithm", "cipher", "algorithm"])
        transfer_size = get_case_insensitive(rp, ["Transfer_Size", "transfer_size", "size"])
        transfer_time = get_case_insensitive(rp, ["Transfer_Time", "transfer_time", "time"])

        src_ip = nc.source_ip or get_case_insensitive(rp, ["SRC_IP", "src_ip", "source_ip"])
        dst_ip = nc.destination_ip or get_case_insensitive(rp, ["DST_IP", "dst_ip", "destination_ip"])
        sport = nc.source_port or get_case_insensitive(rp, ["SOURCE_PORT", "sport"])
        dport = nc.destination_port or get_case_insensitive(rp, ["DESTINATION_PORT", "dport"])

        network = {
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "public_ip": nc.public_ip or src_ip,
            "source_port": int(sport) if sport and str(sport).isdigit() else None,
            "destination_port": int(dport) if dport and str(dport).isdigit() else None,
            "protocol": nc.protocol or "KEM_TLS",
            "country": nc.country,
            "city": nc.city,
            "network_zone": "DMZ",
        }

        severity = sc.severity or get_case_insensitive(rp, ["severity", "level"])
        action = sc.action or get_case_insensitive(rp, ["action", "status"])

        security = {
            "severity": normalize_severity(severity) if severity else "MEDIUM",
            "action": str(action).upper() if action else "ALLOW",
            "encryption_status": f"Quantum Resistant: {cipher}" if cipher else "Traditional TLS",
            "rule_name": f"PQC Anomaly: {anom_type}" if anom_type else None,
            "log_source": sc.log_source or "QuantumSensors",
        }

        # Embed into normalized_event_data
        normalized_data = {
            "anomaly_type": str(anom_type) if anom_type else None,
            "crypto_algorithm": str(cipher) if cipher else None,
            "transfer_size_bytes": int(transfer_size) if transfer_size and str(transfer_size).isdigit() else None,
            "transfer_time_ms": float(transfer_time) if transfer_time is not None else None
        }

        return {
            "identity_context": identity,
            "asset_context": asset,
            "network_context": network,
            "financial_context": {},
            "security_context": security,
            "normalized_event_data": normalized_data
        }
