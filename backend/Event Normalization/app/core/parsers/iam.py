from typing import Dict, Any
from app.core.parsers.base import BaseParser, get_case_insensitive, normalize_severity
from app.core.schema import UniversalEventEnvelope

class IAMParser(BaseParser):
    """Parses Identity & Access Management authentication records."""

    def normalize(self, uee: UniversalEventEnvelope) -> Dict[str, Any]:
        nc = uee.network_context
        sc = uee.security_context
        rp = uee.raw_payload or {}

        identity = self.extract_identity(uee)
        asset = self.extract_assets(uee)

        auth_method = get_case_insensitive(rp, ["Authentication_Method", "auth_method", "method"])
        login_status = get_case_insensitive(rp, ["Login_Status", "login_status", "status"])
        mfa = get_case_insensitive(rp, ["MFA", "mfa", "mfa_used"])

        if auth_method:
            identity["authentication_method"] = str(auth_method)
        if login_status:
            identity["authentication_status"] = str(login_status)
        if mfa:
            identity["mfa_status"] = str(mfa)

        src_ip = nc.source_ip or get_case_insensitive(rp, ["IP", "ip", "source_ip", "Client_IP"])
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
            "log_source": sc.log_source or "IAM",
        }

        normalized_data = {
            "username": identity["username"],
            "authentication_method": identity["authentication_method"],
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
