from datetime import datetime, timezone
from typing import Dict, Any
from pydantic import BaseModel, Field

class Relationship(BaseModel):
    relationship_id: str
    relationship_type: str
    source_node_id: str
    target_node_id: str
    attributes: Dict[str, Any] = Field(default_factory=dict)
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    observation_count: int = 1
    confidence: float = 1.0
    version: int = 1
