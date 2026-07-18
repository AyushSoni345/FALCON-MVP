import threading
from typing import Dict, List, Optional
from module4.app.models.models import CorrelatedSecurityIncident
from module4.app.exceptions.exceptions import RepositoryException

class BoundedDict(dict):
    def __init__(self, max_size: int = 100, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.max_size = max_size

    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        if len(self) > self.max_size:
            first_key = next(iter(self))
            del self[first_key]

class IncidentRepository:
    """
    Thread-safe, in-memory repository to manage the persistence, retrieval,
    and updates of CorrelatedSecurityIncident objects.
    """

    def __init__(self) -> None:
        self._storage: Dict[str, CorrelatedSecurityIncident] = BoundedDict(max_size=100)
        self._lock = threading.Lock()

    def save(self, incident: CorrelatedSecurityIncident) -> CorrelatedSecurityIncident:
        incident_id = incident.incident_info.incident_id
        if not incident_id:
            raise RepositoryException("Cannot save an incident without a valid incident_id.")
            
        with self._lock:
            self._storage[incident_id] = incident
            
        return incident

    def get(self, incident_id: str) -> Optional[CorrelatedSecurityIncident]:
        with self._lock:
            return self._storage.get(incident_id)

    def list_all(self) -> List[CorrelatedSecurityIncident]:
        with self._lock:
            return list(self._storage.values())

    def update(self, incident_id: str, updated_incident: CorrelatedSecurityIncident) -> CorrelatedSecurityIncident:
        with self._lock:
            if incident_id not in self._storage:
                raise RepositoryException(f"Incident with ID '{incident_id}' not found in repository.")
            self._storage[incident_id] = updated_incident
            
        return updated_incident

    def delete(self, incident_id: str) -> bool:
        with self._lock:
            if incident_id in self._storage:
                del self._storage[incident_id]
                return True
            return False

    def search_by_entity(self, entity_name: str) -> List[CorrelatedSecurityIncident]:
        with self._lock:
            return [
                inc for inc in self._storage.values()
                if inc.incident_info.primary_entity.lower() == entity_name.lower()
            ]

    def search_by_type(self, incident_type: str) -> List[CorrelatedSecurityIncident]:
        with self._lock:
            return [
                inc for inc in self._storage.values()
                if inc.incident_info.incident_type.lower() == incident_type.lower()
            ]

    def clear(self) -> None:
        with self._lock:
            self._storage.clear()
