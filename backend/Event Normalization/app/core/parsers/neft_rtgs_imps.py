from typing import Dict, Any
from app.core.parsers.base import BaseParser, get_case_insensitive, normalize_severity
from app.core.schema import UniversalEventEnvelope

class BaseBankTransferParser(BaseParser):
    """Common abstraction for NEFT, RTGS, and IMPS electronic transfers."""

    def _normalize_transfer(self, uee: UniversalEventEnvelope, channel: str) -> Dict[str, Any]:
        nc = uee.network_context
        sc = uee.security_context
        rp = uee.raw_payload or {}

        identity = self.extract_identity(uee)
        asset = self.extract_assets(uee)
        asset["device_type"] = "Bank Transfer Gateway"

        txn_id = get_case_insensitive(rp, ["Transaction_ID", "transaction_id", "TxnID", "TransactionID"])
        sender_acct = get_case_insensitive(rp, ["Sender_Account", "sender_account", "senderAccount"])
        receiver_acct = get_case_insensitive(rp, ["Receiver_Account", "receiver_account", "receiverAccount"])
        receiver_bank = get_case_insensitive(rp, ["Receiver_Bank", "receiver_bank", "receiverBank"])
        receiver_ifsc = get_case_insensitive(rp, ["Receiver_IFSC", "receiver_ifsc", "ifsc"])
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
            "transaction_type": "TRANSFER",
            "payment_channel": channel,
            "amount": amount,
            "currency": "INR",
            "sender_account": str(sender_acct) if sender_acct else identity["account_number"],
            "receiver_account": str(receiver_acct) if receiver_acct else None,
            "beneficiary_id": identity["beneficiary_id"],
            "receiver_bank": str(receiver_bank) if receiver_bank else None,
            "transaction_status": str(status).upper() if status else None,
            "ifsc": str(receiver_ifsc) if receiver_ifsc else None
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
            "network_zone": "Internal",
        }

        severity = sc.severity or get_case_insensitive(rp, ["severity", "level"])
        action = sc.action or get_case_insensitive(rp, ["action", "status"])

        security = {
            "severity": normalize_severity(severity),
            "action": str(action).upper() if action else None,
            "log_source": sc.log_source or channel,
        }

        normalized_data = {
            "transaction_id": financial["transaction_id"],
            "amount": financial["amount"],
            "sender_account": financial["sender_account"],
            "receiver_account": financial["receiver_account"],
            "receiver_bank": financial["receiver_bank"],
            "ifsc": financial["ifsc"]
        }

        return {
            "identity_context": identity,
            "asset_context": asset,
            "network_context": network,
            "financial_context": financial,
            "security_context": security,
            "normalized_event_data": normalized_data
        }

class NEFTParser(BaseBankTransferParser):
    """Parses National Electronic Funds Transfer (NEFT) logs."""
    def normalize(self, uee: UniversalEventEnvelope) -> Dict[str, Any]:
        return self._normalize_transfer(uee, "NEFT")

class RTGSParser(BaseBankTransferParser):
    """Parses Real Time Gross Settlement (RTGS) high-value transfers."""
    def normalize(self, uee: UniversalEventEnvelope) -> Dict[str, Any]:
        return self._normalize_transfer(uee, "RTGS")

class IMPSParser(BaseBankTransferParser):
    """Parses Immediate Payment Service (IMPS) instant transfer logs."""
    def normalize(self, uee: UniversalEventEnvelope) -> Dict[str, Any]:
        return self._normalize_transfer(uee, "IMPS")
