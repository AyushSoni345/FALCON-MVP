from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Set

class StateRepository(ABC):
    """Abstract interface for managing state, behavioral history, and event audits."""

    @abstractmethod
    async def get_beneficiaries(self, account_number: str) -> Set[str]:
        pass

    @abstractmethod
    async def add_beneficiary(self, account_number: str, beneficiary_id: str) -> None:
        pass

    @abstractmethod
    async def get_devices(self, customer_id: str) -> Set[str]:
        pass

    @abstractmethod
    async def add_device(self, customer_id: str, device_id: str) -> None:
        pass

    @abstractmethod
    async def get_last_location_event(self, customer_id: str) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    async def update_last_location_event(self, customer_id: str, lat: float, lon: float, timestamp: str) -> None:
        pass

    @abstractmethod
    async def get_last_transaction_timestamp(self, account_number: str) -> Optional[str]:
        pass

    @abstractmethod
    async def add_transaction(self, account_number: str, amount: float, timestamp: str) -> None:
        pass

    @abstractmethod
    async def get_recent_transactions_count(self, account_number: str, seconds_threshold: float, current_timestamp: str) -> int:
        pass

    @abstractmethod
    async def get_transaction_velocity_hour(self, account_number: str, current_timestamp: str) -> float:
        pass

    # New methods for refactored behavioral features
    @abstractmethod
    async def get_last_login_date(self, username: str) -> Optional[str]:
        pass

    @abstractmethod
    async def add_login_date(self, username: str, date_str: str) -> None:
        pass

    @abstractmethod
    async def get_recent_failed_logins(self, username: str, current_timestamp: str, window_minutes: int) -> int:
        pass

    @abstractmethod
    async def add_failed_login(self, username: str, timestamp: str) -> None:
        pass

    @abstractmethod
    async def get_known_browsers(self, customer_id: str) -> Set[str]:
        pass

    @abstractmethod
    async def add_known_browser(self, customer_id: str, browser: str) -> None:
        pass

    @abstractmethod
    async def get_known_os(self, customer_id: str) -> Set[str]:
        pass

    @abstractmethod
    async def add_known_os(self, customer_id: str, os: str) -> None:
        pass

    @abstractmethod
    async def get_known_ips(self, customer_id: str) -> Set[str]:
        pass

    @abstractmethod
    async def add_known_ip(self, customer_id: str, ip: str) -> None:
        pass

    @abstractmethod
    async def get_last_transaction_date(self, account_number: str) -> Optional[str]:
        pass

    @abstractmethod
    async def add_transaction_date(self, account_number: str, date_str: str) -> None:
        pass

    @abstractmethod
    async def get_recent_atm_usage_count(self, customer_id: str, current_timestamp: str, window_minutes: int) -> int:
        pass

    @abstractmethod
    async def add_atm_usage(self, customer_id: str, timestamp: str) -> None:
        pass

    @abstractmethod
    async def save_normalized_event(self, event_id: str, event_data: Dict[str, Any]) -> None:
        pass

    @abstractmethod
    async def get_normalized_event(self, event_id: str) -> Optional[Dict[str, Any]]:
        pass
