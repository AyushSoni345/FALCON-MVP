from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from src.models.node import Node
from src.models.relationship import Relationship

class GraphStore(ABC):
    @abstractmethod
    def add_node(self, node: Node) -> None:
        pass
        
    @abstractmethod
    def update_node(self, node: Node) -> None:
        pass
        
    @abstractmethod
    def get_node(self, node_id: str) -> Optional[Node]:
        pass
        
    @abstractmethod
    def add_relationship(self, relationship: Relationship) -> None:
        pass
        
    @abstractmethod
    def update_relationship(self, relationship: Relationship) -> None:
        pass
        
    @abstractmethod
    def get_relationship(self, source_id: str, target_id: str, rel_type: str) -> Optional[Relationship]:
        pass
        
    @abstractmethod
    def get_node_neighbors(self, node_id: str) -> List[Dict[str, Any]]:
        """Returns list of dicts with keys: 'node', 'relationship'"""
        pass
        
    @abstractmethod
    def get_shortest_path(self, source_id: str, target_id: str) -> List[str]:
        pass
        
    @abstractmethod
    def get_node_count(self) -> int:
        pass
        
    @abstractmethod
    def get_relationship_count(self) -> int:
        pass
