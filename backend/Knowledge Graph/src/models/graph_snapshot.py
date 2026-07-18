from typing import List, Dict, Any
from pydantic import BaseModel
from .node import Node
from .relationship import Relationship

class GraphPath(BaseModel):
    path_id: str
    path_type: str
    ordered_nodes: List[str]
    path_length: int
    confidence: float

class GraphSnapshot(BaseModel):
    new_nodes: List[Node] = []
    updated_nodes: List[Node] = []
    new_relationships: List[Relationship] = []
    updated_relationships: List[Relationship] = []
    paths: List[GraphPath] = []
    metrics: Dict[str, Any] = {}
