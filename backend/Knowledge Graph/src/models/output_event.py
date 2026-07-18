from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from .input_event import ContextEnrichedEvent
from .node import Node
from .relationship import Relationship
from .graph_snapshot import GraphPath

class GraphStateMetadata(BaseModel):
    total_nodes: int = Field(..., alias="total_nodes")
    total_relationships: int = Field(..., alias="total_relationships")
    last_update_timestamp: str = Field(..., alias="last_update_timestamp")

    model_config = {
        "populate_by_name": True,
        "populate_by_field_name": True
    }

class SecurityGraphEvent(BaseModel):
    event_context: Dict[str, Any] = Field(..., alias="Event Context")
    graph_nodes: List[Node] = Field(..., alias="Graph Nodes")
    graph_relationships: List[Relationship] = Field(..., alias="Graph Relationships")
    graph_paths: List[GraphPath] = Field(..., alias="Graph Paths")
    graph_metrics: Dict[str, Any] = Field(..., alias="Graph Metrics")
    graph_context: Dict[str, Any] = Field(..., alias="Graph Context")
    graph_state_metadata: GraphStateMetadata = Field(..., alias="Graph State Metadata")
    context_enriched_event: ContextEnrichedEvent = Field(..., alias="Context Enriched Event")

    model_config = {
        "populate_by_name": True,
        "populate_by_field_name": True
    }
