from typing import Dict, Any
from app.core.parsers.base import BaseParser, get_case_insensitive, normalize_severity
from app.core.schema import UniversalEventEnvelope

class VPNParser(BaseParser):
    """Parses corporate VPN remote connection logs."""

    def normalize(self, uee: UniversalEventEnvelope) -> Dict[str, Any]:
        nc = uee.network_context
        sc = uee.security_context
        rp = uee.raw_payload or {}

        identity = self.extract_identity(uee)
        asset = self.extract_assets(uee)
        asset["device_type"] = "VPN Gateway"

        vpn_gateway = get_case_insensitive(rp, ["VPN Gateway", "vpn_gateway", "gateway"])
        if vpn_gateway:
            asset["vpn_gateway"] = str(vpn_gateway)

        auth_status = get_case_insensitive(rp, ["Authentication", "authentication", "login_status"])
        mfa_status = get_case_insensitive(rp, ["MFA", "mfa", "mfa_used"])
        if auth_status:
            identity["authentication_status"] = str(auth_status)
        if mfa_status:
            identity["mfa_status"] = str(mfa_status)

        src_ip = nc.source_ip or get_case_insensitive(rp, ["Client_IP", "client_ip", "source_ip", "ip"])
        identity["ip_address"] = src_ip

        network = {
            "source_ip": src_ip,
            "destination_ip": nc.destination_ip,
            "public_ip": nc.public_ip or src_ip,
            "source_port": nc.source_port,
            "destination_port": nc.destination_port or 443,
            "protocol": nc.protocol or "HTTPS",
            "country": nc.country,
            "city": nc.city,
            "network_zone": "DMZ",
            "vpn_used": True,
        }

        severity = sc.severity or get_case_insensitive(rp, ["severity", "level"])
        action = sc.action or get_case_insensitive(rp, ["action", "status"])

        security = {
            "severity": normalize_severity(severity),
            "action": str(action).upper() if action else None,
            "log_source": sc.log_source or "VPN",
        }

        normalized_data = {
            "source_ip": src_ip,
            "vpn_gateway": asset.get("vpn_gateway"),
            "authentication_status": identity["authentication_status"],
            "mfa_status": identity["mfa_status"]
        }

        return {
            "identity_context": identity,
            "asset_context": asset,
            "network_context": network,
            "financial_context": {},
            "security_context": security,
            "normalized_event_data": normalized_data
        }
