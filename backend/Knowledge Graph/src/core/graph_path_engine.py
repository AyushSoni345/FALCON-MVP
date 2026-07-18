from typing import List
from src.storage.graph_store import GraphStore
from src.models.node import Node
from src.models.graph_snapshot import GraphPath
import uuid

class GraphPathEngine:
    def __init__(self, store: GraphStore):
        self.store = store
        
    def discover_paths(self, event_nodes: List[Node]) -> List[GraphPath]:
        paths = []
        customers = [n for n in event_nodes if n.node_type == "Customer"]
        transactions = [n for n in event_nodes if n.node_type == "Transaction"]
        malwares = [n for n in event_nodes if n.node_type == "Malware"]
        endpoints = [n for n in event_nodes if n.node_type == "Endpoint"]

        for cust in customers:
            for txn in transactions:
                path_nodes = self.store.get_shortest_path(cust.node_id, txn.node_id)
                if path_nodes:
                    paths.append(GraphPath(
                        path_id=str(uuid.uuid4()),
                        path_type="Transaction Path",
                        ordered_nodes=path_nodes,
                        path_length=len(path_nodes) - 1,
                        confidence=1.0
                    ))
                    
        for ep in endpoints:
            for mw in malwares:
                path_nodes = self.store.get_shortest_path(ep.node_id, mw.node_id)
                if path_nodes:
                    paths.append(GraphPath(
                        path_id=str(uuid.uuid4()),
                        path_type="Threat Path",
                        ordered_nodes=path_nodes,
                        path_length=len(path_nodes) - 1,
                        confidence=1.0
                    ))

        return paths
