from typing import Dict, Any
from app.core.parsers.base import BaseParser, get_case_insensitive, normalize_severity
from app.core.schema import UniversalEventEnvelope

class UPIParser(BaseParser):
    """Parses Unified Payments Interface (UPI) payment transactions."""

    def normalize(self, uee: UniversalEventEnvelope) -> Dict[str, Any]:
        nc = uee.network_context
        sc = uee.security_context
        rp = uee.raw_payload or {}

        identity = self.extract_identity(uee)
        asset = self.extract_assets(uee)
        asset["device_type"] = "Mobile"

        txn_id = get_case_insensitive(rp, ["Transaction_ID", "transaction_id", "TransactionID"])
        upi_id = get_case_insensitive(rp, ["UPI_ID", "upi_id", "upi"])
        sender_acct = get_case_insensitive(rp, ["Sender_Account", "sender_account", "senderAccount"])
        receiver_upi = get_case_insensitive(rp, ["Receiver_UPI", "receiver_upi", "receiverUpi"])
        receiver_bank = get_case_insensitive(rp, ["Receiver_Bank", "receiver_bank", "receiverBank"])
        merchant = get_case_insensitive(rp, ["Merchant", "merchant"])
        amount_raw = get_case_insensitive(rp, ["Amount", "amount", "amt"])
        status = get_case_insensitive(rp, ["Status", "status"])

        amount = None
        if amount_raw is not None:
            try:
                amount = float(amount_raw)
            except (ValueError, TypeError):
                pass

        financial = {
            "transaction_id": str(txn_id) if txn_id else None,
            "transaction_type": "UPI",
            "payment_channel": "UPI",
            "amount": amount,
            "currency": "INR",
            "sender_account": str(sender_acct) if sender_acct else identity["account_number"],
            "receiver_account": str(receiver_upi) if receiver_upi else None,
            "beneficiary_id": identity["beneficiary_id"],
            "receiver_bank": str(receiver_bank) if receiver_bank else None,
            "merchant": str(merchant) if merchant else None,
            "transaction_status": str(status).upper() if status else None,
        }

        if sender_acct:
            identity["account_number"] = str(sender_acct)

        src_ip = nc.source_ip or get_case_insensitive(rp, ["IP", "ip", "source_ip", "Login_IP"])
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

        severity = sc.severity or get_case_insensitive(rp, ["severity", "level"])
        action = sc.action or get_case_insensitive(rp, ["action", "status"])

        security = {
            "severity": normalize_severity(severity),
            "action": str(action).upper() if action else None,
            "log_source": sc.log_source or "UPI",
        }

        normalized_data = {
            "transaction_id": financial["transaction_id"],
            "upi_id": upi_id,
            "amount": financial["amount"],
            "sender_account": financial["sender_account"],
            "receiver_upi": financial["receiver_account"],
            "receiver_bank": financial["receiver_bank"],
            "merchant": financial["merchant"]
        }

        return {
            "identity_context": identity,
            "asset_context": asset,
            "network_context": network,
            "financial_context": financial,
            "security_context": security,
            "normalized_event_data": normalized_data
        }
