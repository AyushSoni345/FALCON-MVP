import threading
from collections import deque
from typing import Set

class Deduplicator:
    def __init__(self, max_cache_size: int = 100000):
        self.max_cache_size = max_cache_size
        self.seen_set: Set[str] = set()
        self.seen_queue: deque = deque()
        self.lock = threading.Lock()

    def is_duplicate(self, event_id: str) -> bool:
        """Checks if event_id is a duplicate. If not, registers it."""
        with self.lock:
            if event_id in self.seen_set:
                return True
            
            # Register seen ID
            self.seen_set.add(event_id)
            self.seen_queue.append(event_id)
            
            # Bound cache size to prevent memory leaks
            if len(self.seen_queue) > self.max_cache_size:
                oldest = self.seen_queue.popleft()
                self.seen_set.discard(oldest)
                
            return False

    def load_from_list(self, event_ids: list):
        """Pre-populates the cache with historical IDs."""
        with self.lock:
            for ev_id in event_ids:
                if ev_id not in self.seen_set:
                    self.seen_set.add(ev_id)
                    self.seen_queue.append(ev_id)
                    
            # Trim cache to max size
            while len(self.seen_queue) > self.max_cache_size:
                oldest = self.seen_queue.popleft()
                self.seen_set.discard(oldest)
