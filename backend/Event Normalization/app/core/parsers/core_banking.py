from typing import Dict, Any
from app.core.parsers.base import BaseParser, get_case_insensitive, normalize_severity
from app.core.schema import UniversalEventEnvelope

class CoreBankingParser(BaseParser):
    """Parses core banking system transaction records."""

    def normalize(self, uee: UniversalEventEnvelope) -> Dict[str, Any]:
        nc = uee.network_context
        sc = uee.security_context
        rp = uee.raw_payload or {}

        identity = self.extract_identity(uee)
        asset = self.extract_assets(uee)
        asset["device_type"] = "Core Banking Server"

        txn_id = get_case_insensitive(rp, ["Transaction_ID", "transaction_id", "txn_id", "TransactionID"])
        txn_type = get_case_insensitive(rp, ["Transaction_Type", "transaction_type", "type"])
        amount_raw = get_case_insensitive(rp, ["Amount", "amount", "amt"])
        currency = get_case_insensitive(rp, ["Currency", "currency", "curr"], "INR")
        branch = get_case_insensitive(rp, ["Branch", "branch"])
        channel = get_case_insensitive(rp, ["Channel", "channel", "payment_channel"])
        status = get_case_insensitive(rp, ["Status", "status", "transaction_status", "result"])

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
            "transaction_type": str(txn_type) if txn_type else None,
            "payment_channel": str(channel) if channel else "CORE_BRANCH",
            "amount": amount,
            "currency": str(currency),
            "sender_account": identity["account_number"],
            "receiver_account": get_case_insensitive(rp, ["receiver_account", "beneficiary_account"]),
            "beneficiary_id": identity["beneficiary_id"],
            "branch": str(branch) if branch else None,
            "transaction_status": str(status).upper() if status else None,
            "account_balance": account_balance,
        }

        src_ip = nc.source_ip or get_case_insensitive(rp, ["IP", "ip"])
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
        action = sc.action or get_case_insensitive(rp, ["action", "status"])

        security = {
            "severity": normalize_severity(severity),
            "action": str(action).upper() if action else None,
            "log_source": sc.log_source or "CoreBanking",
        }

        normalized_data = {
            "transaction_id": financial["transaction_id"],
            "account_number": identity["account_number"],
            "amount": financial["amount"],
            "currency": financial["currency"],
            "transaction_status": financial["transaction_status"]
        }

        return {
            "identity_context": identity,
            "asset_context": asset,
            "network_context": network,
            "financial_context": financial,
            "security_context": security,
            "normalized_event_data": normalized_data
        }
