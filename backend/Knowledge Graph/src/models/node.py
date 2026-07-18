from datetime import datetime, timezone
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field

class Node(BaseModel):
    node_id: str
    node_type: str
    attributes: Dict[str, Any] = Field(default_factory=dict)
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    observation_count: int = 1
    last_event_uuid: Optional[str] = None
    last_correlation_id: Optional[str] = None
    version: int = 1
