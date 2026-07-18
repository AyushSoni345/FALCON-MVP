from typing import Dict, Any
from app.core.parsers.base import BaseParser, get_case_insensitive, normalize_severity
from app.core.schema import UniversalEventEnvelope

class BeneficiaryParser(BaseParser):
    """Parses payee/beneficiary configuration update and addition logs."""

    def normalize(self, uee: UniversalEventEnvelope) -> Dict[str, Any]:
        nc = uee.network_context
        sc = uee.security_context
        rp = uee.raw_payload or {}

        identity = self.extract_identity(uee)
        asset = self.extract_assets(uee)

        benef_id = get_case_insensitive(rp, ["Beneficiary_ID", "beneficiary_id", "beneficiaryId"])
        benef_name = get_case_insensitive(rp, ["Beneficiary_Name", "beneficiary_name", "name"])
        benef_acct = get_case_insensitive(rp, ["Beneficiary_Account", "beneficiary_account", "account"])
        benef_bank = get_case_insensitive(rp, ["Beneficiary_Bank", "beneficiary_bank", "bank"])
        op_type = get_case_insensitive(rp, ["Operation_Type", "operation_type", "action", "status"])

        if benef_id:
            identity["beneficiary_id"] = str(benef_id)

        financial = {
            "payment_channel": "PORTAL_UPDATE",
            "sender_account": identity["account_number"],
            "receiver_account": str(benef_acct) if benef_acct else None,
            "beneficiary_id": identity["beneficiary_id"],
            "receiver_bank": str(benef_bank) if benef_bank else None,
            "transaction_status": str(op_type).upper() if op_type else None,
        }

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
            "log_source": sc.log_source or "BeneficiaryManager",
        }

        normalized_data = {
            "beneficiary_id": identity["beneficiary_id"],
            "beneficiary_name": str(benef_name) if benef_name else None,
            "beneficiary_account": financial["receiver_account"],
            "operation_type": financial["transaction_status"]
        }

        return {
            "identity_context": identity,
            "asset_context": asset,
            "network_context": network,
            "financial_context": financial,
            "security_context": security,
            "normalized_event_data": normalized_data
        }
