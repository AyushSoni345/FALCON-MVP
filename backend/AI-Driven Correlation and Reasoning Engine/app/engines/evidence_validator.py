from typing import Any, Dict, List
from module4.app.models.models import SecurityGraphEvent
from module4.app.engines.interfaces import BaseEvidenceValidator

class EvidenceValidator(BaseEvidenceValidator):
    """
    Collects, categorizes, and validates supporting or contradictory evidence
    across the entire correlated event set.
    """

    def validate_evidence(
        self,
        events: List[SecurityGraphEvent],
        sequence_output: Dict[str, Any],
        graph_output: Dict[str, Any]
    ) -> Dict[str, Any]:
        related_events = [e.event_context.event_uuid for e in events]
        graph_nodes = [n.node_id for n in graph_output.get("nodes", [])]
        graph_relationships = [r.relationship_id for r in graph_output.get("relationships", [])]
        graph_paths = [p.path_id for p in graph_output.get("paths", [])]

        IOC_matches = []
        malware_matches = []
        fraud_matches = []
        behavioral_anomalies = []
        supporting_logs = []
        contradictory_evidence = []

        # Scrape evidence from events
        for event in events:
            # Check context enriched event for detailed logs or indicators
            enriched = event.context_enriched_event.original_event
            if enriched:
                supporting_logs.append(f"Ingested original logs for event {event.event_context.event_uuid}")
                
            # Node classifications
            for node in event.graph_nodes:
                if node.node_type == "IOC":
                    IOC_matches.append(node.node_id)
                elif node.node_type == "Malware":
                    malware_matches.append(node.node_id)
                elif node.node_type == "Beneficiary" and node.properties.get("is_flagged"):
                    fraud_matches.append(node.node_id)

            # Look for anomalies
            for rel in event.graph_relationships:
                if rel.relationship_status.lower() in ["anomaly", "suspicious", "flagged"]:
                    behavioral_anomalies.append(
                        f"Relationship {rel.relationship_id} status is '{rel.relationship_status}'"
                    )

            # Contradictory evidence detection
            # Example: A relationship exists with 0.0 confidence, or status is explicitly 'authorized' or 'whitelist'
            for rel in event.graph_relationships:
                if rel.relationship_status.lower() in ["authorized", "whitelisted", "benign"]:
                    contradictory_evidence.append(
                        f"Benign relationship: Node '{rel.source_node}' -> '{rel.target_node}' is marked '{rel.relationship_status}'"
                    )

        # Evidence quality scoring (0.0 to 1.0)
        # Score increases with number of distinct sources and low contradictions
        base_score = 0.4
        base_score += min(0.3, 0.05 * len(related_events))
        base_score += min(0.2, 0.05 * (len(IOC_matches) + len(malware_matches) + len(fraud_matches)))
        
        # Deduct if there are contradictions
        if contradictory_evidence:
            base_score = max(0.1, base_score - 0.1 * len(contradictory_evidence))

        evidence_score = round(min(1.0, base_score), 2)
        validation_status = "VALID" if evidence_score >= 0.3 else "INSUFFICIENT"

        return {
            "related_events": related_events,
            "graph_paths": graph_paths,
            "graph_nodes": graph_nodes,
            "graph_relationships": graph_relationships,
            "IOC_matches": list(set(IOC_matches)),
            "malware_matches": list(set(malware_matches)),
            "fraud_matches": list(set(fraud_matches)),
            "behavioral_anomalies": list(set(behavioral_anomalies)),
            "supporting_logs": supporting_logs,
            "contradictory_evidence": contradictory_evidence,
            "evidence_score": evidence_score,
            "validation_status": validation_status
        }
