from typing import Dict, Any
from app.core.parsers.base import BaseParser, get_case_insensitive, normalize_severity
from app.core.schema import UniversalEventEnvelope

class EDRParser(BaseParser):
    """Parses Endpoint Detection & Response (EDR) agent system logs (CrowdStrike, Defender, etc.)."""

    def normalize(self, uee: UniversalEventEnvelope) -> Dict[str, Any]:
        nc = uee.network_context
        sc = uee.security_context
        rp = uee.raw_payload or {}

        identity = self.extract_identity(uee)
        asset = self.extract_assets(uee)
        asset["device_type"] = "Workstation"

        host_name = get_case_insensitive(rp, ["Host_Name", "host_name", "host", "hostname"])
        if host_name:
            asset["asset_name"] = str(host_name)

        proc_name = get_case_insensitive(rp, ["Process_Name", "process_name", "process", "proc"])
        proc_hash = get_case_insensitive(rp, ["Process_Hash", "process_hash", "hash", "sha256"])
        mal_name = get_case_insensitive(rp, ["Malware_Name", "malware_name", "threat"])
        det_status = get_case_insensitive(rp, ["Detection_Status", "detection_status", "status"])
        
        cpu_raw = get_case_insensitive(rp, ["CPU_Usage", "cpu_usage", "cpu"])
        mem_raw = get_case_insensitive(rp, ["Memory_Usage", "memory_usage", "memory"])
        
        cpu_val = None
        mem_val = None
        if cpu_raw is not None:
            try:
                cpu_val = float(str(cpu_raw).rstrip("%"))
            except ValueError:
                pass
        if mem_raw is not None:
            try:
                mem_val = float(str(mem_raw).rstrip("%"))
            except ValueError:
                pass

        src_ip = nc.source_ip or get_case_insensitive(rp, ["IP", "ip", "source_ip", "host_ip"])
        identity["ip_address"] = src_ip

        network = {
            "source_ip": src_ip,
            "destination_ip": nc.destination_ip,
            "public_ip": nc.public_ip or src_ip,
            "source_port": nc.source_port,
            "destination_port": nc.destination_port,
            "protocol": nc.protocol,
            "country": nc.country,
            "city": nc.city,
            "network_zone": "Internal",
        }

        severity = sc.severity or get_case_insensitive(rp, ["severity", "level"])
        action = sc.action or get_case_insensitive(rp, ["action", "result"])

        security = {
            "severity": normalize_severity(severity),
            "action": str(action).upper() if action else None,
            "process_name": str(proc_name) if proc_name else None,
            "process_hash": str(proc_hash) if proc_hash else None,
            "malware_name": str(mal_name) if mal_name else None,
            "detection_status": str(det_status).upper() if det_status else None,
            "cpu_usage": cpu_val,
            "memory_usage": mem_val,
            "sensor_id": sc.sensor_id,
            "log_source": sc.log_source or "EDR_Agent",
        }

        normalized_data = {
            "hostname": asset["asset_name"],
            "process_name": security["process_name"],
            "process_hash": security["process_hash"],
            "malware_name": security["malware_name"],
            "detection_status": security["detection_status"]
        }

        return {
            "identity_context": identity,
            "asset_context": asset,
            "network_context": network,
            "financial_context": {},
            "security_context": security,
            "normalized_event_data": normalized_data
        }
