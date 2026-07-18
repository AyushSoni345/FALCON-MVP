import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Set
from app.database.repository import StateRepository
from app.logging_config import log_pipeline

class BoundedDict(dict):
    def __init__(self, max_size: int = 10000, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.max_size = max_size

    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        if len(self) > self.max_size:
            first_key = next(iter(self))
            del self[first_key]

class InMemoryStateRepository(StateRepository):
    """
    In-memory state database tracking login histories, browser fingerprints, IPs,
    failed logins, and rolling transaction schedules for downstream behavioral analysis.
    """

    def __init__(self):
        self.beneficiaries = BoundedDict(max_size=10000)
        self.devices = BoundedDict(max_size=10000)
        self.last_locations = BoundedDict(max_size=10000)
        self.transaction_history = BoundedDict(max_size=10000)
        self.normalized_events = BoundedDict(max_size=10000)

        self.user_login_dates = BoundedDict(max_size=10000)
        self.failed_logins = BoundedDict(max_size=10000)
        self.known_browsers = BoundedDict(max_size=10000)
        self.known_os = BoundedDict(max_size=10000)
        self.known_ips = BoundedDict(max_size=10000)
        self.account_transaction_dates = BoundedDict(max_size=10000)
        self.atm_usages = BoundedDict(max_size=10000)

    def _parse_ts(self, ts_str: str) -> datetime:
        try:
            return datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except ValueError:
            clean_ts = ts_str.split(".")[0].rstrip("Z")
            try:
                return datetime.strptime(clean_ts, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
            except ValueError:
                return datetime.utcnow().replace(tzinfo=timezone.utc)

    async def get_beneficiaries(self, account_number: str) -> Set[str]:
        return self.beneficiaries.get(account_number, set())

    async def add_beneficiary(self, account_number: str, beneficiary_id: str) -> None:
        if account_number not in self.beneficiaries:
            self.beneficiaries[account_number] = set()
        self.beneficiaries[account_number].add(beneficiary_id)

    async def get_devices(self, customer_id: str) -> Set[str]:
        return self.devices.get(customer_id, set())

    async def add_device(self, customer_id: str, device_id: str) -> None:
        if customer_id not in self.devices:
            self.devices[customer_id] = set()
        self.devices[customer_id].add(device_id)

    async def get_last_location_event(self, customer_id: str) -> Optional[Dict[str, Any]]:
        return self.last_locations.get(customer_id)

    async def update_last_location_event(self, customer_id: str, lat: float, lon: float, timestamp: str) -> None:
        self.last_locations[customer_id] = {
            "latitude": lat,
            "longitude": lon,
            "timestamp": timestamp
        }

    async def get_last_transaction_timestamp(self, account_number: str) -> Optional[str]:
        history = self.transaction_history.get(account_number, [])
        if not history:
            return None
        sorted_history = sorted(history, key=lambda x: self._parse_ts(x["timestamp"]))
        return sorted_history[-1]["timestamp"]

    async def add_transaction(self, account_number: str, amount: float, timestamp: str) -> None:
        if account_number not in self.transaction_history:
            self.transaction_history[account_number] = []
        self.transaction_history[account_number].append({
            "amount": amount,
            "timestamp": timestamp
        })

    async def get_recent_transactions_count(self, account_number: str, seconds_threshold: float, current_timestamp: str) -> int:
        history = self.transaction_history.get(account_number, [])
        if not history:
            return 0
        current_dt = self._parse_ts(current_timestamp)
        count = 0
        for tx in history:
            tx_dt = self._parse_ts(tx["timestamp"])
            time_diff = (current_dt - tx_dt).total_seconds()
            if 0 <= time_diff <= seconds_threshold:
                count += 1
        return count

    async def get_transaction_velocity_hour(self, account_number: str, current_timestamp: str) -> float:
        history = self.transaction_history.get(account_number, [])
        if not history:
            return 0.0
        current_dt = self._parse_ts(current_timestamp)
        total_amount = 0.0
        for tx in history:
            tx_dt = self._parse_ts(tx["timestamp"])
            time_diff = (current_dt - tx_dt).total_seconds()
            if 0 <= time_diff <= 3600:
                total_amount += tx["amount"]
        return total_amount

    async def get_last_login_date(self, username: str) -> Optional[str]:
        dates = self.user_login_dates.get(username, [])
        return dates[-1] if dates else None

    async def add_login_date(self, username: str, date_str: str) -> None:
        if username not in self.user_login_dates:
            self.user_login_dates[username] = []
        self.user_login_dates[username].append(date_str)

    async def get_recent_failed_logins(self, username: str, current_timestamp: str, window_minutes: int) -> int:
        failures = self.failed_logins.get(username, [])
        if not failures:
            return 0
        current_dt = self._parse_ts(current_timestamp)
        count = 0
        for f in failures:
            f_dt = self._parse_ts(f)
            time_diff = (current_dt - f_dt).total_seconds() / 60.0
            if 0 <= time_diff <= window_minutes:
                count += 1
        return count

    async def add_failed_login(self, username: str, timestamp: str) -> None:
        if username not in self.failed_logins:
            self.failed_logins[username] = []
        self.failed_logins[username].append(timestamp)

    async def get_known_browsers(self, customer_id: str) -> Set[str]:
        return self.known_browsers.get(customer_id, set())

    async def add_known_browser(self, customer_id: str, browser: str) -> None:
        if customer_id not in self.known_browsers:
            self.known_browsers[customer_id] = set()
        self.known_browsers[customer_id].add(browser)

    async def get_known_os(self, customer_id: str) -> Set[str]:
        return self.known_os.get(customer_id, set())

    async def add_known_os(self, customer_id: str, os: str) -> None:
        if customer_id not in self.known_os:
            self.known_os[customer_id] = set()
        self.known_os[customer_id].add(os)

    async def get_known_ips(self, customer_id: str) -> Set[str]:
        return self.known_ips.get(customer_id, set())

    async def add_known_ip(self, customer_id: str, ip: str) -> None:
        if customer_id not in self.known_ips:
            self.known_ips[customer_id] = set()
        self.known_ips[customer_id].add(ip)

    async def get_last_transaction_date(self, account_number: str) -> Optional[str]:
        dates = self.account_transaction_dates.get(account_number, [])
        return dates[-1] if dates else None

    async def add_transaction_date(self, account_number: str, date_str: str) -> None:
        if account_number not in self.account_transaction_dates:
            self.account_transaction_dates[account_number] = []
        self.account_transaction_dates[account_number].append(date_str)

    async def get_recent_atm_usage_count(self, customer_id: str, current_timestamp: str, window_minutes: int) -> int:
        usages = self.atm_usages.get(customer_id, [])
        if not usages:
            return 0
        current_dt = self._parse_ts(current_timestamp)
        count = 0
        for u in usages:
            u_dt = self._parse_ts(u)
            time_diff = (current_dt - u_dt).total_seconds() / 60.0
            if 0 <= time_diff <= window_minutes:
                count += 1
        return count

    async def add_atm_usage(self, customer_id: str, timestamp: str) -> None:
        if customer_id not in self.atm_usages:
            self.atm_usages[customer_id] = []
        self.atm_usages[customer_id].append(timestamp)

    async def save_normalized_event(self, event_id: str, event_data: Dict[str, Any]) -> None:
        event_uuid = event_data.get("event_information", {}).get("event_uuid") or event_id
        corr_id = event_data.get("event_information", {}).get("correlation_id")
        
        log_pipeline(
            logging.DEBUG,
            "Repository Save Started",
            "repository_save",
            "started",
            event_uuid=event_uuid,
            correlation_id=corr_id
        )
        
        self.normalized_events[event_id] = event_data
        
        log_pipeline(
            logging.DEBUG,
            "Repository Save Completed",
            "repository_save",
            "success",
            event_uuid=event_uuid,
            correlation_id=corr_id
        )

    async def get_normalized_event(self, event_id: str) -> Optional[Dict[str, Any]]:
        return self.normalized_events.get(event_id)
