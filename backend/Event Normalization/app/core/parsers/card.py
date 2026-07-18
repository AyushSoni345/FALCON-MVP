from typing import Dict, Any
from app.core.parsers.base import BaseParser, get_case_insensitive, normalize_severity
from app.core.schema import UniversalEventEnvelope

class CardParser(BaseParser):
    """Parses Credit/Debit card Point of Sale (POS) and online transactions."""

    def normalize(self, uee: UniversalEventEnvelope) -> Dict[str, Any]:
        nc = uee.network_context
        sc = uee.security_context
        rp = uee.raw_payload or {}

        identity = self.extract_identity(uee)
        asset = self.extract_assets(uee)
        asset["device_type"] = "POS Terminal"

        pos_terminal = get_case_insensitive(rp, ["POS_Terminal", "pos_terminal", "posId", "terminal_id"])
        if pos_terminal:
            asset["pos_terminal"] = str(pos_terminal)

        txn_id = get_case_insensitive(rp, ["Transaction_ID", "transaction_id", "TxnID", "TransactionID"])
        card_num = get_case_insensitive(rp, ["Card_Number", "card_number", "cardNumber", "Card_Number_Masked"])
        mcc = get_case_insensitive(rp, ["MCC", "mcc", "merchant_category_code"])
        merchant = get_case_insensitive(rp, ["Merchant", "merchant", "merchant_name"])
        amount_raw = get_case_insensitive(rp, ["Amount", "amount", "amt"])
        status = get_case_insensitive(rp, ["Status", "status"])
        card_country = get_case_insensitive(rp, ["Card_Country", "card_country", "country"])
        card_city = get_case_insensitive(rp, ["Card_City", "card_city", "city"])

        amount = None
        if amount_raw is not None:
            try:
                amount = float(amount_raw)
            except (ValueError, TypeError):
                pass

        financial = {
            "transaction_id": str(txn_id) if txn_id else None,
            "transaction_type": "CARD",
            "payment_channel": "CARD_POS" if pos_terminal else "CARD_ONLINE",
            "amount": amount,
            "currency": "INR",
            "sender_account": identity["account_number"],
            "beneficiary_id": identity["beneficiary_id"],
            "merchant": str(merchant) if merchant else None,
            "merchant_category": str(mcc) if mcc else None,
            "transaction_status": str(status).upper() if status else None,
        }

        if card_num:
            identity["card_number_masked"] = str(card_num)

        src_ip = nc.source_ip or get_case_insensitive(rp, ["IP", "ip", "client_ip"])
        identity["ip_address"] = src_ip

        network = {
            "source_ip": src_ip,
            "destination_ip": nc.destination_ip,
            "public_ip": nc.public_ip or src_ip,
            "source_port": nc.source_port,
            "destination_port": nc.destination_port or 443,
            "protocol": nc.protocol or "HTTPS",
            "country": nc.country or card_country,
            "city": nc.city or card_city,
            "network_zone": "External",
        }

        # Handle Card geo context overrides
        geo_info = {}
        if card_country:
            gps_lat = get_case_insensitive(rp, ["latitude", "lat"])
            gps_lon = get_case_insensitive(rp, ["longitude", "lon"])
            geo_info = {
                "country": str(card_country),
                "city": str(card_city) if card_city else None,
                "latitude": float(gps_lat) if gps_lat else None,
                "longitude": float(gps_lon) if gps_lon else None,
                "geo_source": "Card_Terminal_Geo"
            }

        severity = sc.severity or get_case_insensitive(rp, ["severity", "level"])
        action = sc.action or get_case_insensitive(rp, ["action", "status"])

        security = {
            "severity": normalize_severity(severity),
            "action": str(action).upper() if action else None,
            "log_source": sc.log_source or "CardEngine",
        }

        normalized_data = {
            "transaction_id": financial["transaction_id"],
            "card_number_masked": identity["card_number_masked"],
            "amount": financial["amount"],
            "merchant": financial["merchant"],
            "mcc": financial["merchant_category"]
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
