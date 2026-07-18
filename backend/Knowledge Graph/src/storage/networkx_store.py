import networkx as nx
from typing import List, Dict, Any, Optional
from src.models.node import Node
from src.models.relationship import Relationship
from src.storage.graph_store import GraphStore

class NetworkXGraphStore(GraphStore):
    def __init__(self):
        self.graph = nx.MultiDiGraph()
        
    def _prune_graph(self) -> None:
        max_nodes = 10000
        if self.graph.number_of_nodes() > max_nodes:
            oldest_node = min(
                self.graph.nodes(data=True),
                key=lambda n: n[1].get("last_seen").isoformat() if hasattr(n[1].get("last_seen"), "isoformat") else (n[1].get("last_seen") or "")
            )
            node_to_remove = oldest_node[0]
            self.graph.remove_node(node_to_remove)

    def add_node(self, node: Node) -> None:
        self.graph.add_node(node.node_id, **node.model_dump())
        self._prune_graph()
        
    def update_node(self, node: Node) -> None:
        if self.graph.has_node(node.node_id):
            nx.set_node_attributes(self.graph, {node.node_id: node.model_dump()})
        else:
            self.add_node(node)
            
    def get_node(self, node_id: str) -> Optional[Node]:
        if self.graph.has_node(node_id):
            return Node(**self.graph.nodes[node_id])
        return None
        
    def add_relationship(self, relationship: Relationship) -> None:
        self.graph.add_edge(
            relationship.source_node_id, 
            relationship.target_node_id, 
            key=relationship.relationship_type,
            **relationship.model_dump()
        )
        
    def update_relationship(self, relationship: Relationship) -> None:
        if self.graph.has_edge(relationship.source_node_id, relationship.target_node_id, key=relationship.relationship_type):
            self.graph[relationship.source_node_id][relationship.target_node_id][relationship.relationship_type].update(relationship.model_dump())
        else:
            self.add_relationship(relationship)
            
    def get_relationship(self, source_id: str, target_id: str, rel_type: str) -> Optional[Relationship]:
        if self.graph.has_edge(source_id, target_id, key=rel_type):
            data = self.graph[source_id][target_id][rel_type]
            return Relationship(**data)
        return None
        
    def get_node_neighbors(self, node_id: str) -> List[Dict[str, Any]]:
        neighbors = []
        if not self.graph.has_node(node_id):
            return neighbors
            
        # Get successors
        for target_id in self.graph.successors(node_id):
            for rel_type, rel_data in self.graph[node_id][target_id].items():
                neighbors.append({
                    "node": Node(**self.graph.nodes[target_id]),
                    "relationship": Relationship(**rel_data)
                })
                
        # Get predecessors
        for source_id in self.graph.predecessors(node_id):
            for rel_type, rel_data in self.graph[source_id][node_id].items():
                neighbors.append({
                    "node": Node(**self.graph.nodes[source_id]),
                    "relationship": Relationship(**rel_data)
                })
                
        return neighbors
        
    def get_shortest_path(self, source_id: str, target_id: str) -> List[str]:
        if not self.graph.has_node(source_id) or not self.graph.has_node(target_id):
            return []
        try:
            return nx.shortest_path(self.graph, source=source_id, target=target_id)
        except nx.NetworkXNoPath:
            return []
            
    def get_node_count(self) -> int:
        return self.graph.number_of_nodes()
        
    def get_relationship_count(self) -> int:
        return self.graph.number_of_edges()

    def get_underlying_graph(self) -> nx.MultiDiGraph:
        """Expose NetworkX graph specifically for graph metrics engine."""
        return self.graph
