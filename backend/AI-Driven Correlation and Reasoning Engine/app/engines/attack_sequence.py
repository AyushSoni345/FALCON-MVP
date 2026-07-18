from typing import Any, Dict, List
from module4.app.models.models import SecurityGraphEvent, TimelineStep
from module4.app.engines.interfaces import BaseAttackSequenceEngine

class AttackSequenceEngine(BaseAttackSequenceEngine):
    """
    Reconstructs the multi-stage attack timeline.
    Determines entry points, exits, progression milestones, and lateral movement hops.
    """

    def reconstruct(
        self,
        events: List[SecurityGraphEvent],
        temporal_output: Dict[str, Any],
        graph_output: Dict[str, Any],
        patterns_output: Dict[str, Any]
    ) -> Dict[str, Any]:
        ordered_events = temporal_output.get("ordered_events", [])
        
        timeline_steps: List[TimelineStep] = []
        entry_point = "Unknown Entry"
        exit_point = "Unknown Exit"
        lateral_movements = []

        if not ordered_events:
            return {
                "timeline_steps": [],
                "entry_point": entry_point,
                "exit_point": exit_point,
                "lateral_movements": []
            }

        # Determine entry point (typically first node in first event or primary entity)
        first_event = ordered_events[0]
        entry_point = first_event.graph_context.primary_entity
        
        # Check if first event contains a source IP/VPN gateway/User login
        for node in first_event.graph_nodes:
            if node.node_type in ["IP Address", "VPN Gateway", "User"]:
                entry_point = f"{node.node_type}:{node.node_id}"
                break

        # Reconstruct sequence
        for idx, event in enumerate(ordered_events):
            action = event.event_context.event_type
            primary_entity = event.graph_context.primary_entity
            
            # Formulate step confidence from event context/metadata
            step_confidence = 0.8
            if event.graph_relationships:
                # Average relationship extraction confidence
                conf_sum = sum(r.confidence for r in event.graph_relationships)
                step_confidence = conf_sum / len(event.graph_relationships)

            step = TimelineStep(
                sequence_number=idx + 1,
                timestamp=event.event_context.normalized_timestamp,
                event_uuid=event.event_context.event_uuid,
                action=action,
                entity=primary_entity,
                confidence=round(step_confidence, 2)
            )
            timeline_steps.append(step)

            # Look for lateral movements (e.g. CONNECTED_TO relationships where target differs from start)
            for rel in event.graph_relationships:
                if rel.relationship_type in ["CONNECTED_TO", "ACCESSED"] and rel.source_node != rel.target_node:
                    lateral_movements.append(
                        f"Lateral movement from {rel.source_node} to {rel.target_node} via {rel.relationship_type}"
                    )

        # Determine exit point (typically the objective of the last event, e.g. transaction or data source)
        last_event = ordered_events[-1]
        exit_point = last_event.graph_context.primary_entity
        for node in last_event.graph_nodes:
            if node.node_type in ["Transaction", "Beneficiary", "Server"]:
                exit_point = f"{node.node_type}:{node.node_id}"
                break

        return {
            "timeline_steps": timeline_steps,
            "entry_point": entry_point,
            "exit_point": exit_point,
            "lateral_movements": list(set(lateral_movements))
        }
