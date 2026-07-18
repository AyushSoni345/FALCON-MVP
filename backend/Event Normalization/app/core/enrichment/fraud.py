import math
import logging
from datetime import datetime, timezone
from typing import Dict, Any
from app.core.enrichment.base import BaseEnricher
from app.database.repository import StateRepository
from app.config import settings
from app.logging_config import log_pipeline

BLACKLISTED_ACCOUNTS = {"ACC-MULE-882", "ACC-SCAM-901"}
RISKY_MERCHANTS = {"evil-gambling.com", "sketchy-crypto-exchange.io"}
HIGH_RISK_COUNTRIES = {"Russia", "North Korea", "Iran"}

class FraudContextEngine(BaseEnricher):
    """
    Evaluates transactional parameters to populate fraud evidence context.
    Module 2 only computes features and evidence; it does not classify fraud.
    """

    def __init__(self, repo: StateRepository):
        self.repo = repo

    def _mask(self, val: Any) -> str:
        if not val:
            return "None"
        val_str = str(val)
        if len(val_str) <= 4:
            return "****"
        return f"{val_str[:2]}****{val_str[-2:]}"

    def _parse_ts(self, ts_str: str) -> datetime:
        try:
            return datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except ValueError:
            clean_ts = ts_str.split(".")[0].rstrip("Z")
            try:
                return datetime.strptime(clean_ts, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
            except ValueError:
                return datetime.utcnow().replace(tzinfo=timezone.utc)

    async def enrich_async(self, event: Dict[str, Any]) -> Dict[str, Any]:
        fc = event.get("fraud_context", {})
        ident = event.get("identity_context", {})
        txn = event.get("financial_context", {})
        geo = event.get("geo_context", {})
        raw = event.get("raw_payload", {})
        info = event.get("event_information", {})

        event_uuid = info.get("event_uuid")
        corr_id = info.get("correlation_id")

        log_pipeline(
            logging.DEBUG,
            "Calculating stateful fraud indicators.",
            "fraud_enrichment",
            "started",
            event_uuid=event_uuid,
            correlation_id=corr_id
        )

        cust_id = ident.get("customer_id")
        acct_num = ident.get("account_number")
        beneficiary_id = ident.get("beneficiary_id") or txn.get("beneficiary_id")
        current_ts_str = info.get("normalized_timestamp") or datetime.utcnow().replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        txn_amount = txn.get("amount")

        # 1. Large Transfer Check
        if txn_amount is not None:
            if txn_amount >= settings.high_value_transaction_threshold:
                fc["large_transfer"] = True

        # 2. First Time Payee Check
        if acct_num and beneficiary_id:
            known_beneficiaries = await self.repo.get_beneficiaries(acct_num)
            if not known_beneficiaries or beneficiary_id not in known_beneficiaries:
                fc["first_time_payee"] = True
                fc["new_payee"] = True
            await self.repo.add_beneficiary(acct_num, beneficiary_id)

        # 3. Blacklisted & Mule account checks
        if acct_num in BLACKLISTED_ACCOUNTS or txn.get("receiver_account") in BLACKLISTED_ACCOUNTS:
            fc["blacklisted_account"] = True
            fc["mule_account"] = True

        if beneficiary_id and beneficiary_id in BLACKLISTED_ACCOUNTS:
            fc["high_risk_beneficiary"] = True

        # 4. High Risk Country check
        country = geo.get("country") or event.get("network_context", {}).get("country")
        if country in HIGH_RISK_COUNTRIES:
            fc["high_risk_country"] = True

        # 5. Risky & New Merchant Check
        merchant = txn.get("merchant")
        if merchant:
            if merchant in RISKY_MERCHANTS:
                fc["risky_merchant"] = True
            
            pos = event.get("asset_context", {}).get("pos_terminal")
            if pos:
                fc["new_merchant"] = True

        # 6. Velocity / Rapid beneficiary additions
        event_type = info.get("event_type", "").upper()
        if event_type == "BENEFICIARY" and cust_id:
            await self.repo.add_atm_usage(cust_id, current_ts_str)
            usage_count = await self.repo.get_recent_atm_usage_count(cust_id, current_ts_str, 15)
            if usage_count > 2:
                fc["rapid_beneficiary_addition"] = True

        # 7. Update transaction rolling records & calculate velocity
        if acct_num and txn_amount is not None:
            await self.repo.add_transaction(acct_num, txn_amount, current_ts_str)
            velocity_sum = await self.repo.get_transaction_velocity_hour(acct_num, current_ts_str)
            fc["velocity_indicator"] = velocity_sum
            
            if velocity_sum > 1000000.0:
                fc["unusual_transaction_pattern"] = True

        event["fraud_context"] = fc
        
        masked_account = self._mask(acct_num)
        log_pipeline(
            logging.DEBUG,
            f"Stateful fraud attributes computed for account {masked_account}: LargeTransfer={fc.get('large_transfer')}, FirstPayee={fc.get('first_time_payee')}",
            "fraud_enrichment",
            "success",
            event_uuid=event_uuid,
            correlation_id=corr_id
        )

        return event

    def enrich(self, event: Dict[str, Any]) -> Dict[str, Any]:
        import asyncio
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                return asyncio.run_coroutine_threadsafe(self.enrich_async(event), loop).result()
            else:
                return loop.run_until_complete(self.enrich_async(event))
        except Exception:
            return event
