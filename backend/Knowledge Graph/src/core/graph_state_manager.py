from datetime import datetime, timezone
from typing import Dict, Tuple, List, Any
from src.models.node import Node
from src.models.relationship import Relationship
from src.storage.graph_store import GraphStore
from src.core.graph_index_manager import GraphIndexManager

class GraphStateManager:
    def __init__(self, store: GraphStore, index_manager: GraphIndexManager):
        self.store = store
        self.index_manager = index_manager
        
    def add_or_update_node(self, node: Node, event_uuid: str, correlation_id: str) -> Tuple[Node, bool]:
        """
        Returns (node, is_new)
        Uses index_manager to find existing node based on unique identifiers in attributes.
        """
        now = datetime.now(timezone.utc)
        # Find existing node using index
        existing_node_id = None
        for key, value in node.attributes.items():
            if isinstance(value, str):
                existing_node_id = self.index_manager.get_node_id(key, value)
                if existing_node_id:
                    break
        
        if existing_node_id:
            existing_node = self.store.get_node(existing_node_id)
            if existing_node:
                # Update existing node
                existing_node.last_seen = now
                existing_node.observation_count += 1
                existing_node.last_event_uuid = event_uuid
                existing_node.last_correlation_id = correlation_id
                existing_node.version += 1
                
                # Merge attributes
                existing_node.attributes.update(node.attributes)
                self.store.update_node(existing_node)
                
                return existing_node, False
                
        # Register new node
        node.first_seen = now
        node.last_seen = now
        node.observation_count = 1
        node.last_event_uuid = event_uuid
        node.last_correlation_id = correlation_id
        node.version = 1
        self.store.add_node(node)
        
        # Add to index
        for key, value in node.attributes.items():
            if isinstance(value, str):
                self.index_manager.add_index(key, value, node.node_id)
                
        return node, True
        
    def add_or_update_relationship(self, relationship: Relationship) -> Tuple[Relationship, bool]:
        """
        Returns (relationship, is_new)
        """
        now = datetime.now(timezone.utc)
        existing_rel = self.store.get_relationship(
            relationship.source_node_id, 
            relationship.target_node_id, 
            relationship.relationship_type
        )
        
        if existing_rel:
            existing_rel.last_seen = now
            existing_rel.observation_count += 1
            existing_rel.confidence = min(1.0, existing_rel.confidence + 0.1) # simplistic confidence update
            existing_rel.version += 1
            existing_rel.attributes.update(relationship.attributes)
            self.store.update_relationship(existing_rel)
            return existing_rel, False
            
        relationship.first_seen = now
        relationship.last_seen = now
        relationship.observation_count = 1
        relationship.version = 1
        self.store.add_relationship(relationship)
        return relationship, True

    def get_metadata(self) -> Dict[str, Any]:
        return {
            "total_nodes": self.store.get_node_count(),
            "total_relationships": self.store.get_relationship_count(),
            "last_update_timestamp": datetime.now(timezone.utc).isoformat()
        }
