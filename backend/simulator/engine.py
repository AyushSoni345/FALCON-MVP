import os
import json
import time
import sys
import random
import threading
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
import urllib.request

from simulator.config import state
from simulator.scenarios import build_scenario_events, SCENARIOS_MAP

class SimulationEngine:
    def __init__(self):
        self.event_queue: List[Dict[str, Any]] = []  # Items: {"run_at": float, "event": CommonEnvelope}
        self.lock = threading.Lock()
        self.thread: Optional[threading.Thread] = None
        self.next_session_start = 0.0
        
        # CLI Output Options
        self.output_mode = "file"  # "file", "stdout", "http"
        self.http_url = ""         # Target URL for HTTP POST ingestion
        self.verbose = False       # Print engine status logs to stderr

    def start(self):
        if state.running:
            return
        state.running = True
        self.next_session_start = time.time()
        self.thread = threading.Thread(target=self._run_loop, daemon=True)
        self.thread.start()

    def stop(self):
        state.running = False
        if self.thread:
            self.thread.join(timeout=1.0)
            self.thread = None

    def trigger_scenario_manually(self, name: str):
        """Instantly schedules a scenario to run starting now."""
        now_dt = datetime.now(timezone.utc)
        now_t = time.time()
        try:
            built_events = build_scenario_events(name, now_dt)
            with self.lock:
                for i, ev in enumerate(built_events):
                    ev_dt = datetime.strptime(ev.timestamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
                    offset = (ev_dt - now_dt).total_seconds()
                    
                    self.event_queue.append({
                        "run_at": now_t + offset,
                        "event": ev
                    })
                # Sort queue by run_at
                self.event_queue.sort(key=lambda x: x["run_at"])
            
            if self.verbose:
                sys.stderr.write(f"[*] Scheduled scenario: {name} ({len(built_events)} events, Correlation: {built_events[0].correlation_id})\n")
        except Exception as e:
            sys.stderr.write(f"[!] Error triggering scenario {name}: {e}\n")

    def _send_http_post(self, event_dict: Dict[str, Any]):
        """Sends event payload via HTTP POST using urllib (avoiding external requests library dependency)."""
        try:
            data = json.dumps(event_dict).encode('utf-8')
            req = urllib.request.Request(
                self.http_url, 
                data=data, 
                headers={'Content-Type': 'application/json'}
            )
            with urllib.request.urlopen(req, timeout=2.0) as response:
                response.read()  # Consume response
        except Exception as e:
            if self.verbose:
                sys.stderr.write(f"[!] HTTP Ingestion Error sending to {self.http_url}: {e}\n")

    def _run_loop(self):
        # Prepare output file if in file mode
        if self.output_mode == "file":
            os.makedirs(os.path.dirname(state.log_path), exist_ok=True)
            if self.verbose:
                sys.stderr.write(f"[*] Logging events to file: {state.log_path}\n")
        elif self.output_mode == "stdout" and self.verbose:
            sys.stderr.write(f"[*] Directing events to standard output (stdout)\n")
        elif self.output_mode == "http" and self.verbose:
            sys.stderr.write(f"[*] Ingesting events directly to HTTP endpoint: {self.http_url}\n")

        while state.running:
            now = time.time()
            
            # 1. Schedule a new session if timer expired
            rate = state.rate
            delay_between_sessions = 4.0 / rate
            
            # Apply time-of-day traffic scaling factor
            curr_hour = datetime.now().hour
            if curr_hour >= 23 or curr_hour < 6:
                factor = 3.0   # Night: low traffic (slow down starts by 3x)
            elif curr_hour >= 6 and curr_hour < 9:
                factor = 1.2   # Early morning: normal-low
            elif curr_hour >= 9 and curr_hour < 17:
                factor = 0.6   # Work hours: high volume (speed up starts by 1.6x)
            elif curr_hour >= 17 and curr_hour < 21:
                factor = 0.7   # Evening peak: high volume (speed up starts by 1.4x)
            else:
                factor = 1.0   # Late evening: normal
                
            adjusted_delay = delay_between_sessions * factor
            
            if now >= self.next_session_start:
                ratio = state.malicious_ratio
                is_malicious = random.random() < ratio
                
                if is_malicious:
                    attack_types = [k for k in SCENARIOS_MAP.keys() if k.startswith("attack_")]
                    scen = random.choice(attack_types)
                else:
                    normal_types = [k for k in SCENARIOS_MAP.keys() if k.startswith("normal_")]
                    scen = random.choice(normal_types)
                
                self.trigger_scenario_manually(scen)
                
                # Jitter of +/- 30%
                jitter = random.uniform(0.7, 1.3)
                self.next_session_start = now + (adjusted_delay * jitter)
            
            # 2. Check for ready events
            ready_events = []
            with self.lock:
                while self.event_queue and self.event_queue[0]["run_at"] <= now:
                    ready_events.append(self.event_queue.pop(0))
            
            # 3. Emit events
            for item in ready_events:
                ev = item["event"]
                ev_dict = ev.model_dump()
                ev_json = json.dumps(ev_dict)
                
                # Output based on mode
                if self.output_mode == "stdout":
                    sys.stdout.write(ev_json + "\n")
                    sys.stdout.flush()
                elif self.output_mode == "file":
                    try:
                        with open(state.log_path, "a", encoding="utf-8") as f:
                            f.write(ev_json + "\n")
                    except Exception as e:
                        sys.stderr.write(f"[!] Error writing to log file: {e}\n")
                elif self.output_mode == "http":
                    # Send asynchronously or inline
                    # Since we are in the thread loop, inline is fine for modest rates
                    self._send_http_post(ev_dict)
                
                state.increment_event_count()
            
            # Sleep calculation
            with self.lock:
                if self.event_queue:
                    next_run = self.event_queue[0]["run_at"]
                    sleep_time = min(0.1, max(0.01, next_run - now))
                else:
                    sleep_time = min(0.1, max(0.01, self.next_session_start - now))
            
            time.sleep(sleep_time)

engine = SimulationEngine()
