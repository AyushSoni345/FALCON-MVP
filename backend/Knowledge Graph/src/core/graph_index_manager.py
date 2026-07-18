from typing import Dict, Optional

class BoundedDict(dict):
    def __init__(self, max_size: int = 10000, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.max_size = max_size

    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        if len(self) > self.max_size:
            first_key = next(iter(self))
            del self[first_key]

class GraphIndexManager:
    def __init__(self):
        # Maps (entity_type, entity_value) -> node_id
        # e.g., ("Customer ID", "CUST-123") -> "node-1"
        self._index: Dict[str, Dict[str, str]] = {}
        
    def add_index(self, entity_type: str, entity_value: str, node_id: str) -> None:
        if entity_type not in self._index:
            self._index[entity_type] = BoundedDict(max_size=10000)
        self._index[entity_type][entity_value] = node_id
        
    def get_node_id(self, entity_type: str, entity_value: str) -> Optional[str]:
        return self._index.get(entity_type, {}).get(entity_value)
