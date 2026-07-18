from typing import Dict, Any
from app.core.parsers.base import BaseParser, get_case_insensitive, normalize_severity
from app.core.schema import UniversalEventEnvelope

class ATMParser(BaseParser):
    """Parses physical ATM banking machine withdrawal/deposit events."""

    def normalize(self, uee: UniversalEventEnvelope) -> Dict[str, Any]:
        nc = uee.network_context
        sc = uee.security_context
        rp = uee.raw_payload or {}

        identity = self.extract_identity(uee)
        asset = self.extract_assets(uee)
        asset["device_type"] = "ATM"

        atm_id = get_case_insensitive(rp, ["ATM_ID", "atm_id", "atmId"])
        if atm_id:
            asset["atm_id"] = str(atm_id)

        txn_id = get_case_insensitive(rp, ["Transaction_ID", "transaction_id", "TxnID", "TransactionID"])
        amount_raw = get_case_insensitive(rp, ["Amount", "amount", "amt"])
        card_num = get_case_insensitive(rp, ["Card_Number", "card_number", "cardNumber", "Card_Number_Masked"])
        status = get_case_insensitive(rp, ["Status", "status"])
        atm_loc = get_case_insensitive(rp, ["ATM_Location", "atm_location", "location"])
        
        amount = None
        if amount_raw is not None:
            try:
                amount = float(amount_raw)
            except (ValueError, TypeError):
                pass

        bal_after = get_case_insensitive(rp, ["Balance_After", "balance_after", "balance"])
        account_balance = None
        if bal_after is not None:
            try:
                account_balance = float(bal_after)
            except (ValueError, TypeError):
                pass

        financial = {
            "transaction_id": str(txn_id) if txn_id else None,
            "transaction_type": "ATM_WITHDRAWAL",
            "payment_channel": "ATM",
            "amount": amount,
            "currency": "INR",
            "sender_account": identity["account_number"],
            "beneficiary_id": identity["beneficiary_id"],
            "branch": str(atm_loc) if atm_loc else None,
            "transaction_status": str(status).upper() if status else None,
            "account_balance": account_balance,
        }

        if card_num:
            identity["card_number_masked"] = str(card_num)

        src_ip = nc.source_ip or get_case_insensitive(rp, ["IP", "ip", "atm_ip"])
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

        # Retrieve direct physical coordinates
        geo_info = {}
        gps = get_case_insensitive(rp, ["GPS", "gps"])
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

        if gps_lat is not None and gps_lon is not None:
            geo_info = {
                "latitude": float(gps_lat),
                "longitude": float(gps_lon),
                "geo_source": "ATM_GPS"
            }

        severity = sc.severity or get_case_insensitive(rp, ["severity", "level"])
        action = sc.action or get_case_insensitive(rp, ["action", "status"])

        security = {
            "severity": normalize_severity(severity),
            "action": str(action).upper() if action else None,
            "log_source": sc.log_source or "ATMEngine",
        }

        normalized_data = {
            "transaction_id": financial["transaction_id"],
            "atm_id": asset.get("atm_id"),
            "amount": financial["amount"],
            "account_balance": financial["account_balance"]
        }

        result = {
            "identity_context": identity,
            "asset_context": asset,
            "network_context": network,
            "financial_context": financial,
            "security_context": security,
            "normalized_event_data": normalized_data
        }

        if geo_info:
            result["geo_context"] = geo_info

        return result
