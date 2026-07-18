from typing import Dict, Any, Optional
from pydantic import BaseModel, Field

class ContextEnrichedEvent(BaseModel):
    """
    Represents the black-box event coming from Module 2.
    It contains dynamic fields, so we accept arbitrary dictionary data
    but provide a structured base if needed.
    """
    event_uuid: Optional[str] = Field(None, description="Unique identifier for the event")
    correlation_id: Optional[str] = Field(None, description="Correlation identifier")
    timestamp: Optional[str] = Field(None, description="Event generation time")
    
    # We use a catch-all configuration for unknown fields
    model_config = {
        "extra": "allow"
    }
