import threading
from datetime import datetime
from typing import Dict, Optional, Tuple

class ChronologyManager:
    def __init__(self):
        # Maps session_id -> datetime of last event
        self.session_times: Dict[str, datetime] = {}
        # Maps correlation_id -> datetime of last event
        self.correlation_times: Dict[str, datetime] = {}
        self.lock = threading.Lock()

    def check_and_update(self, timestamp_str: str, session_id: Optional[str] = None, correlation_id: Optional[str] = None) -> Tuple[bool, str]:
        """
        Validates that the incoming timestamp is not prior to the last seen event for the session/correlation.
        Returns (is_valid, error_message).
        """
        try:
            current_time = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%SZ")
        except Exception as e:
            return False, f"Failed to parse timestamp during chronology check: {e}"

        with self.lock:
            # 1. Session ID Check
            if session_id:
                last_time = self.session_times.get(session_id)
                if last_time and current_time < last_time:
                    return False, f"Chronology violation: Event timestamp '{timestamp_str}' is prior to session '{session_id}' last timestamp '{last_time.strftime('%Y-%m-%dT%H:%M:%SZ')}'"

            # 2. Correlation ID Check
            if correlation_id:
                last_time = self.correlation_times.get(correlation_id)
                if last_time and current_time < last_time:
                    return False, f"Chronology violation: Event timestamp '{timestamp_str}' is prior to correlation '{correlation_id}' last timestamp '{last_time.strftime('%Y-%m-%dT%H:%M:%SZ')}'"

            # 3. Update timestamps
            if session_id:
                self.session_times[session_id] = current_time
            if correlation_id:
                self.correlation_times[correlation_id] = current_time

            return True, ""

    def load_historical_record(self, timestamp_str: str, session_id: Optional[str] = None, correlation_id: Optional[str] = None):
        """Loads historical times. Does not raise violations; just updates the max timestamp seen."""
        try:
            current_time = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            return

        with self.lock:
            if session_id:
                last = self.session_times.get(session_id)
                if not last or current_time > last:
                    self.session_times[session_id] = current_time
            if correlation_id:
                last = self.correlation_times.get(correlation_id)
                if not last or current_time > last:
                    self.correlation_times[correlation_id] = current_time
