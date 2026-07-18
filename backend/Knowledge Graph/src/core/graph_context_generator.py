from typing import Dict, Any, List
from src.storage.graph_store import GraphStore
from src.models.node import Node

class GraphContextGenerator:
    def __init__(self, store: GraphStore):
        self.store = store
        
    def generate_context(self, event_nodes: List[Node]) -> Dict[str, Any]:
        context = {
            "primary_entities": [],
            "related_entities": [],
            "connected_devices": [],
            "connected_ips": [],
            "active_sessions": [],
            "linked_transactions": [],
            "risk_neighborhood": []
        }
        
        for node in event_nodes:
            context["primary_entities"].append(node.node_id)
            
            neighbors = self.store.get_node_neighbors(node.node_id)
            for n_data in neighbors:
                neighbor_node = n_data["node"]
                rel = n_data["relationship"]
                
                context["related_entities"].append({
                    "node_id": neighbor_node.node_id,
                    "node_type": neighbor_node.node_type,
                    "relationship_type": rel.relationship_type
                })
                
                if neighbor_node.node_type == "Device":
                    context["connected_devices"].append(neighbor_node.node_id)
                elif neighbor_node.node_type == "IP Address":
                    context["connected_ips"].append(neighbor_node.node_id)
                elif neighbor_node.node_type == "Session":
                    context["active_sessions"].append(neighbor_node.node_id)
                elif neighbor_node.node_type == "Transaction":
                    context["linked_transactions"].append(neighbor_node.node_id)
                elif neighbor_node.node_type in ["Malware", "Threat Actor", "IOC"]:
                    context["risk_neighborhood"].append({
                        "threat_id": neighbor_node.node_id,
                        "type": neighbor_node.node_type
                    })
                    
        for k, v in context.items():
            if v and isinstance(v[0], str):
                context[k] = list(set(v))
                
        return context
