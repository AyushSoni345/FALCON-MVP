from typing import Dict, Any, List
import networkx as nx
from src.storage.graph_store import GraphStore
from src.models.node import Node

class GraphMetricsEngine:
    def __init__(self, store: GraphStore):
        self.store = store
        
    def compute_metrics(self, event_nodes: List[Node]) -> Dict[str, Any]:
        metrics = {
            "node_metrics": {},
            "graph_level_metrics": {}
        }
        
        if not hasattr(self.store, "get_underlying_graph"):
            return metrics
            
        nx_graph = self.store.get_underlying_graph()
        
        for node in event_nodes:
            if not nx_graph.has_node(node.node_id):
                continue
                
            in_degree = nx_graph.in_degree(node.node_id)
            out_degree = nx_graph.out_degree(node.node_id)
            degree = in_degree + out_degree
            
            metrics["node_metrics"][node.node_id] = {
                "degree": degree,
                "in_degree": in_degree,
                "out_degree": out_degree
            }
            
        metrics["graph_level_metrics"]["total_nodes"] = nx_graph.number_of_nodes()
        metrics["graph_level_metrics"]["total_edges"] = nx_graph.number_of_edges()
        try:
            metrics["graph_level_metrics"]["density"] = nx.density(nx_graph)
        except Exception:
            metrics["graph_level_metrics"]["density"] = 0.0
            
        try:
            # We use an undirected version of the multidigraph for components
            undirected = nx.Graph(nx_graph)
            components = nx.number_connected_components(undirected)
            metrics["graph_level_metrics"]["connected_components"] = components
        except Exception:
            pass

        return metrics
