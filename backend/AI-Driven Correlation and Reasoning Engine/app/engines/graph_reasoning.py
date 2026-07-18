from typing import Any, Dict, List, Set
from module4.app.models.models import SecurityGraphEvent, GraphNode, GraphRelationship, GraphPath
from module4.app.engines.interfaces import BaseGraphReasoningEngine

class GraphReasoningEngine(BaseGraphReasoningEngine):
    """
    Analyzes graph structures from all events in the correlation batch.
    Identifies shared entities, traversed paths, and multi-hop node connections.
    """

    def reason(self, events: List[SecurityGraphEvent], temporal_output: Dict[str, Any]) -> Dict[str, Any]:
        aggregated_nodes: Dict[str, GraphNode] = {}
        aggregated_relationships: Dict[str, GraphRelationship] = {}
        aggregated_paths: Dict[str, GraphPath] = {}
        
        # Track which node IDs are associated with each entity type
        nodes_by_type: Dict[str, Set[str]] = {}
        # Track which events reference which nodes
        node_event_references: Dict[str, Set[str]] = {}

        for event in events:
            ev_uuid = event.event_context.event_uuid
            
            for node in event.graph_nodes:
                aggregated_nodes[node.node_id] = node
                nodes_by_type.setdefault(node.node_type, set()).add(node.node_id)
                node_event_references.setdefault(node.node_id, set()).add(ev_uuid)
                
            for rel in event.graph_relationships:
                aggregated_relationships[rel.relationship_id] = rel
                
            for path in event.graph_paths:
                aggregated_paths[path.path_id] = path

        # Find shared entities (nodes referenced by more than one event)
        shared_entities: Dict[str, Dict[str, Any]] = {}
        for node_id, ref_events in node_event_references.items():
            if len(ref_events) > 1:
                node = aggregated_nodes[node_id]
                shared_entities[node_id] = {
                    "node_type": node.node_type,
                    "event_count": len(ref_events),
                    "referenced_events": list(ref_events),
                    "properties": node.properties
                }

        # Identify multi-hop connections (chains of relationships)
        # Build adjacency list
        adj_list: Dict[str, List[str]] = {}
        for rel in aggregated_relationships.values():
            adj_list.setdefault(rel.source_node, []).append(rel.target_node)

        # Build graph observations
        observations = []
        if shared_entities:
            observations.append(
                f"Identified {len(shared_entities)} shared entity/entities: " +
                ", ".join(f"{nid} ({info['node_type']} across {info['event_count']} events)" for nid, info in shared_entities.items())
            )
        else:
            observations.append("No shared entities found across events in the current graph state.")

        # Identify path metrics
        shortest_paths_info = {}
        for event in events:
            metrics = event.graph_metrics
            for path_type in ["shortest_path_to_customer", "shortest_path_to_transaction", "shortest_path_to_endpoint"]:
                val = getattr(metrics, path_type)
                if val is not None:
                    shortest_paths_info[path_type] = min(shortest_paths_info.get(path_type, 999), val)

        for path_type, hops in shortest_paths_info.items():
            observations.append(f"Minimum {path_type.replace('_', ' ')} is {hops} hops.")

        # Graph confidence score based on connected density and shared paths
        graph_confidence = 0.5
        if shared_entities:
            graph_confidence += min(0.4, 0.1 * len(shared_entities))
        if aggregated_paths:
            graph_confidence += 0.1

        return {
            "nodes": list(aggregated_nodes.values()),
            "relationships": list(aggregated_relationships.values()),
            "paths": list(aggregated_paths.values()),
            "shared_entities": shared_entities,
            "adjacency_list": adj_list,
            "observations": observations,
            "graph_confidence": min(1.0, graph_confidence)
        }
