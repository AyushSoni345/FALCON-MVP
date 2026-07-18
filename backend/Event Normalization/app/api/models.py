from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional

class HealthResponse(BaseModel):
    status: str = Field(examples=["healthy"])
    environment: str = Field(examples=["production"])
    version: str = Field(examples=["2.0.0"])

class SchemaResponse(BaseModel):
    schema_name: str = Field(examples=["FALCON Canonical Output Schema"])
    version: str = Field(examples=["2.0.0"])
    supported_event_types: List[str]
    supported_parsers: List[str]
    supported_enrichment_engines: List[str]

class MetricsResponse(BaseModel):
    events_processed: int
    average_processing_time: float
    failed_events: int
    parser_statistics: Dict[str, int]
    cache_hit_ratio: float
    geo_lookup_count: int
    threat_lookup_count: int
    fraud_lookup_count: int
    repository_size: int

class ErrorResponse(BaseModel):
    error_code: str = Field(examples=["UNSUPPORTED_EVENT_TYPE"])
    error_message: str = Field(examples=["No supported parser found for event type: INVALID_TYPE"])
    processing_stage: str = Field(examples=["parser_selection"])
    event_uuid: Optional[str] = Field(None, examples=["abcd-1234-efgh-5678"])
    recommended_action: str = Field(examples=["Check if the metadata.event_type field matches one of the 17 supported types."])
