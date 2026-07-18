import uuid
from typing import List
from src.models.node import Node
from src.models.relationship import Relationship
from src.core.graph_rules_engine import GraphRulesEngine

class RelationshipEngine:
    def __init__(self, rules_engine: GraphRulesEngine):
        self.rules_engine = rules_engine
        
    def build_relationships(self, nodes: List[Node]) -> List[Relationship]:
        relationships = []
        inferred = self.rules_engine.infer_relationships(nodes)
        
        for source, target, rel_type in inferred:
            rel = Relationship(
                relationship_id=str(uuid.uuid4()),
                relationship_type=rel_type,
                source_node_id=source.node_id,
                target_node_id=target.node_id,
                attributes={}
            )
            relationships.append(rel)
            
        return relationships
