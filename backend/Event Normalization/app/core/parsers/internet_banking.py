from typing import Dict, Any
from app.core.parsers.base import BaseParser, get_case_insensitive, normalize_severity
from app.core.schema import UniversalEventEnvelope

class InternetBankingParser(BaseParser):
    """Parses digital/internet banking portal transactions and login activity."""

    def normalize(self, uee: UniversalEventEnvelope) -> Dict[str, Any]:
        nc = uee.network_context
        sc = uee.security_context
        rp = uee.raw_payload or {}

        identity = self.extract_identity(uee)
        asset = self.extract_assets(uee)
        asset["device_type"] = "Mobile" if "mobile" in str(asset.get("browser", "")).lower() else "Laptop"

        browser = get_case_insensitive(rp, ["Browser", "browser", "user_agent"])
        os = get_case_insensitive(rp, ["OS", "os", "operating_system"])
        if browser:
            asset["browser"] = str(browser)
        if os:
            asset["operating_system"] = str(os)

        login_status = get_case_insensitive(rp, ["Login_Status", "login_status", "status"])
        if login_status:
            identity["authentication_status"] = str(login_status)

        src_ip = nc.source_ip or get_case_insensitive(rp, ["IP", "ip", "source_ip", "Login_IP", "login_ip"])
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
            "network_zone": "External",
        }

        gps = get_case_insensitive(rp, ["GPS", "gps", "location"])
        gps_lat = None
        gps_lon = None
        if gps and isinstance(gps, dict):
            gps_lat = gps.get("latitude", gps.get("lat"))
            gps_lon = gps.get("longitude", gps.get("lon"))
        elif gps and isinstance(gps, str) and "," in gps:
            parts = gps.split(",")
            try:
                gps_lat = float(parts[0])
                gps_lon = float(parts[1])
            except ValueError:
                pass

        geo_info = {}
        if gps_lat is not None and gps_lon is not None:
            geo_info = {
                "latitude": float(gps_lat),
                "longitude": float(gps_lon),
                "geo_source": "GPS_Simulator"
            }

        severity = sc.severity or get_case_insensitive(rp, ["severity", "level"])
        action = sc.action or get_case_insensitive(rp, ["action", "result"])

        security = {
            "severity": normalize_severity(severity),
            "action": str(action).upper() if action else None,
            "log_source": sc.log_source or "InternetBanking",
        }

        normalized_data = {
            "customer_id": identity["customer_id"],
            "account_number": identity["account_number"],
            "authentication_status": identity["authentication_status"],
            "ip_address": src_ip
        }

        result = {
            "identity_context": identity,
            "asset_context": asset,
            "network_context": network,
            "financial_context": {},
            "security_context": security,
            "normalized_event_data": normalized_data
        }

        if geo_info:
            result["geo_context"] = geo_info

        return result
