import os
import threading

class SimulationState:
    def __init__(self):
        self._lock = threading.Lock()
        self._running = False
        self._rate = 1.0  # events per second
        self._malicious_ratio = 0.35  # 35% malicious, 65% normal
        self._log_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "events.ndjson"))
        self._event_count = 0

    @property
    def running(self):
        with self._lock:
            return self._running

    @running.setter
    def running(self, value: bool):
        with self._lock:
            self._running = value

    @property
    def rate(self):
        with self._lock:
            return self._rate

    @rate.setter
    def rate(self, value: float):
        with self._lock:
            self._rate = max(0.1, min(1000.0, value))

    @property
    def malicious_ratio(self):
        with self._lock:
            return self._malicious_ratio

    @malicious_ratio.setter
    def malicious_ratio(self, value: float):
        with self._lock:
            self._malicious_ratio = max(0.0, min(1.0, value))

    @property
    def log_path(self):
        with self._lock:
            return self._log_path

    @log_path.setter
    def log_path(self, value: str):
        with self._lock:
            self._log_path = os.path.abspath(value)

    @property
    def event_count(self):
        with self._lock:
            return self._event_count

    def increment_event_count(self):
        with self._lock:
            self._event_count += 1
            return self._event_count

state = SimulationState()
