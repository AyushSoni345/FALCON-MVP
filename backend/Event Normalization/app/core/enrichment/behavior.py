import math
import logging
from datetime import datetime, timezone
from typing import Dict, Any
from app.core.enrichment.base import BaseEnricher
from app.database.repository import StateRepository
from app.config import settings
from app.logging_config import log_pipeline

def haversine_dist(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    R = 6371.0
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat / 2)**2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2)**2
    c = 2 * math.asin(math.sqrt(a))
    return R * c

class BehavioralFeatureEngine(BaseEnricher):
    """
    Computes lightweight, deterministic behavioral features from event contexts and state histories.
    Features are inputs for later AI correlation modules.
    """

    def __init__(self, repo: StateRepository):
        self.repo = repo

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
        bf = event.get("behavioral_features", {})
        ident = event.get("identity_context", {})
        asset = event.get("asset_context", {})
        geo = event.get("geo_context", {})
        txn = event.get("financial_context", {})
        sec = event.get("security_context", {})
        info = event.get("event_information", {})

        event_uuid = info.get("event_uuid")
        corr_id = info.get("correlation_id")

        log_pipeline(
            logging.DEBUG,
            "Initiating client/server behavioral feature checks.",
            "behavioral_features",
            "started",
            event_uuid=event_uuid,
            correlation_id=corr_id
        )

        cust_id = ident.get("customer_id")
        username = ident.get("username")
        device_id = ident.get("device_id")
        acct_num = ident.get("account_number")
        ip_address = ident.get("ip_address")
        event_type = info.get("event_type", "").upper()
        current_ts_str = info.get("normalized_timestamp") or datetime.utcnow().replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        current_dt = self._parse_ts(current_ts_str)

        # 1. New Device check
        if cust_id and device_id:
            known_devices = await self.repo.get_devices(cust_id)
            if not known_devices or device_id not in known_devices:
                bf["new_device"] = True
                event["fraud_context"]["new_device"] = True

        # 2. Browser & OS history checks
        browser = asset.get("browser")
        os = asset.get("operating_system")
        if cust_id and browser:
            known = await self.repo.get_known_browsers(cust_id)
            if not known or browser not in known:
                bf["new_browser"] = True
            await self.repo.add_known_browser(cust_id, browser)

        if cust_id and os:
            known = await self.repo.get_known_os(cust_id)
            if not known or os not in known:
                bf["new_operating_system"] = True
            await self.repo.add_known_os(cust_id, os)

        # 3. IP & Location history checks
        country = geo.get("country")
        city = geo.get("city")
        if cust_id and ip_address:
            known = await self.repo.get_known_ips(cust_id)
            if not known or ip_address not in known:
                bf["new_ip"] = True
                bf["new_network"] = True
            await self.repo.add_known_ip(cust_id, ip_address)

        # 4. Login patterns
        if username:
            today_date = current_dt.strftime("%Y-%m-%d")
            last_login_date = await self.repo.get_last_login_date(username)
            if not last_login_date or last_login_date != today_date:
                bf["first_login_today"] = True
            await self.repo.add_login_date(username, today_date)

            hour = current_dt.hour
            if hour < 6 or hour > 22:
                bf["unusual_login_hour"] = True

            action = sec.get("action", "").upper()
            if event_type == "IAM" and ("FAIL" in action or "BLOCK" in action or "LOCK" in action):
                await self.repo.add_failed_login(username, current_ts_str)
                failed_count = await self.repo.get_recent_failed_logins(username, current_ts_str, 15)
                if failed_count >= 3:
                    bf["multiple_failed_logins"] = True

        # 5. Financial feature generation
        txn_amount = txn.get("amount")
        if acct_num and txn_amount is not None:
            if txn_amount >= 100000.0:
                bf["high_transaction_amount"] = True

            recent_count = await self.repo.get_recent_transactions_count(acct_num, 60.0, current_ts_str)
            if recent_count > 3:
                bf["repeated_transactions"] = True

            if country and country != "Internal Network" and country.lower() != "india":
                bf["foreign_transaction"] = True

        # 6. ATM behavioral features
        if cust_id and "ATM" in event_type:
            await self.repo.add_atm_usage(cust_id, current_ts_str)
            atm_usages = await self.repo.get_recent_atm_usage_count(cust_id, current_ts_str, 60)
            if atm_usages > 3:
                bf["multiple_atm_usage"] = True

        # 7. CPU & Memory anomalies
        cpu = sec.get("cpu_usage")
        mem = sec.get("memory_usage")
        if cpu and cpu > 90.0:
            bf["abnormal_cpu_usage"] = True
        if mem and mem > 90.0:
            bf["abnormal_memory_usage"] = True

        raw = event.get("raw_payload", {})
        tx_size = raw.get("transfer_size", raw.get("Transfer_Size"))
        if tx_size is not None:
            try:
                size_bytes = int(tx_size)
                if size_bytes > 5 * 1024 * 1024 * 1024:
                    bf["large_archive_access"] = True
                if size_bytes > 1 * 1024 * 1024 * 1024:
                    bf["bulk_encrypted_transfer"] = True
            except ValueError:
                pass

        # 8. Impossible Travel
        lat = geo.get("latitude")
        lon = geo.get("longitude")
        if cust_id and lat is not None and lon is not None and lat != 0.0 and lon != 0.0:
            last_loc = await self.repo.get_last_location_event(cust_id)
            if last_loc:
                last_lat = last_loc["latitude"]
                last_lon = last_loc["longitude"]
                last_ts_str = last_loc["timestamp"]
                last_dt = self._parse_ts(last_ts_str)

                time_diff = (current_dt - last_dt).total_seconds() / 3600.0
                if time_diff > 0:
                    dist = haversine_dist(last_lat, last_lon, lat, lon)
                    speed = dist / time_diff
                    if speed > settings.impossible_travel_threshold_kph and dist > 5.0:
                        bf["possible_impossible_travel"] = True
                        event["fraud_context"]["impossible_travel"] = True

        # 9. New Beneficiary check
        if acct_num and (ident.get("beneficiary_id") or txn.get("beneficiary_id")):
            benef_id = ident.get("beneficiary_id") or txn.get("beneficiary_id")
            known_benefs = await self.repo.get_beneficiaries(acct_num)
            if not known_benefs or benef_id not in known_benefs:
                bf["new_beneficiary"] = True

        event["behavioral_features"] = bf
        
        log_pipeline(
            logging.DEBUG,
            "Behavioral analysis completed successfully.",
            "behavioral_features",
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
