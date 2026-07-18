import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List
from module4.app.models.models import (
    SecurityGraphEvent,
    CorrelatedSecurityIncident,
    IncidentInformation,
    CorrelatedEvidence,
    AttackGraph,
    AIReasoning,
    ThreatHypothesis,
    ConfidenceAssessment,
    IncidentContext,
    InvestigationContext,
    ReferencedSecurityGraphEvent
)
from module4.app.engines.interfaces import BaseIncidentBuilder

class IncidentBuilder(BaseIncidentBuilder):
    """
    Assembles the outputs from all reasoning engines into a unified
    CorrelatedSecurityIncident container.
    """

    def build_incident(
        self,
        events: List[SecurityGraphEvent],
        temporal_output: Dict[str, Any],
        graph_output: Dict[str, Any],
        patterns_output: Dict[str, Any],
        sequence_output: Dict[str, Any],
        evidence_output: Dict[str, Any],
        hypotheses: List[ThreatHypothesis],
        confidence_output: Dict[str, Any]
    ) -> CorrelatedSecurityIncident:
        incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
        
        # Primary classification/type from recognized patterns
        patterns = patterns_output.get("detected_patterns", ["Unknown Threat Pattern"])
        incident_type = patterns[0] if patterns else "Unknown Threat Pattern"
        
        # Category classification
        incident_category = "Cyber"
        if "Financial Fraud" in patterns or "Account Takeover" in patterns:
            incident_category = "Hybrid" if len(patterns) > 1 else "Financial"

        # Timing
        ordered_events = temporal_output.get("ordered_events", events)
        start_time = ordered_events[0].event_context.normalized_timestamp if ordered_events else datetime.now(timezone.utc)
        end_time = ordered_events[-1].event_context.normalized_timestamp if ordered_events else datetime.now(timezone.utc)
        duration = temporal_output.get("duration_seconds", 0.0)

        # Primary Entity
        primary_entity = events[0].graph_context.primary_entity if events else "Unknown"

        # Impacted Assets
        nodes = graph_output.get("nodes", [])
        relationships = graph_output.get("relationships", [])
        affected_assets = len(nodes)

        # 1. Incident Information
        info = IncidentInformation(
            incident_id=incident_id,
            incident_type=incident_type,
            incident_category=incident_category,
            incident_status="Active",
            incident_start_time=start_time,
            incident_end_time=end_time,
            incident_duration=duration,
            primary_entity=primary_entity,
            affected_assets=affected_assets,
            correlated_event_count=len(events)
        )

        # 2. Correlated Evidence
        evidence = CorrelatedEvidence(
            related_events=evidence_output.get("related_events", []),
            graph_paths=evidence_output.get("graph_paths", []),
            graph_nodes=evidence_output.get("graph_nodes", []),
            graph_relationships=evidence_output.get("graph_relationships", []),
            IOC_matches=evidence_output.get("IOC_matches", []),
            malware_matches=evidence_output.get("malware_matches", []),
            fraud_matches=evidence_output.get("fraud_matches", []),
            behavioral_anomalies=evidence_output.get("behavioral_anomalies", []),
            supporting_logs=evidence_output.get("supporting_logs", [])
        )

        # 3. Attack Graph
        # Build subgraph specific to the incident
        attack_graph = AttackGraph(
            attack_nodes=nodes,
            attack_relationships=relationships,
            attack_paths=graph_output.get("paths", []),
            attack_entry_point=sequence_output.get("entry_point", "Unknown"),
            attack_exit_point=sequence_output.get("exit_point", "Unknown"),
            lateral_movements=sequence_output.get("lateral_movements", [])
        )

        # 4. AI Reasoning - Compile actual graph and temporal observations
        temporal_observations = temporal_output.get("observations", [])
        graph_observations = graph_output.get("observations", [])
        
        reasoning_chain = []
        for idx, step in enumerate(sequence_output.get("timeline_steps", [])):
            reasoning_chain.append(
                f"Step {step.sequence_number}: Action '{step.action}' observed on entity '{step.entity}' at {step.timestamp.isoformat()}."
            )
            
        reasoning = AIReasoning(
            reasoning_chain=reasoning_chain if reasoning_chain else ["Correlated events chronologically and traversed entity connections."],
            supporting_patterns=patterns,
            graph_observations=graph_observations if graph_observations else ["Analyzed relationship paths between nodes."],
            temporal_observations=temporal_observations if temporal_observations else ["Calculated event sequence timeline."],
            anomaly_summary=f"Validation status is '{evidence_output.get('validation_status', 'VALID')}' with an evidence quality score of {evidence_output.get('evidence_score', 0.5)}.",
            relationship_summary=f"Incident type '{incident_type}' inferred based on matching patterns: {', '.join(patterns)}."
        )

        # 5. Confidence Assessment
        confidence = ConfidenceAssessment(
            overall_confidence=confidence_output.get("overall_confidence", 0.5),
            temporal_confidence=confidence_output.get("temporal_confidence", 0.5),
            graph_confidence=confidence_output.get("graph_confidence", 0.5),
            behavioral_confidence=confidence_output.get("behavioral_confidence", 0.5),
            threat_intelligence_confidence=confidence_output.get("threat_intelligence_confidence", 0.5),
            fraud_confidence=confidence_output.get("fraud_confidence", 0.5),
            evidence_score=confidence_output.get("evidence_score", 0.5),
            uncertainty_score=confidence_output.get("uncertainty_score", 0.5)
        )

        # 6. Incident Context
        affected_customers = []
        affected_employees = []
        affected_accounts = []
        affected_transactions = []
        affected_devices = []
        affected_servers = []
        affected_applications = []
        business_process = "Enterprise IT Operations"

        for node in nodes:
            nid = node.node_id
            nt = node.node_type
            if nt == "Customer":
                affected_customers.append(nid)
            elif nt == "Employee":
                affected_employees.append(nid)
            elif nt == "Account":
                affected_accounts.append(nid)
            elif nt == "Transaction":
                affected_transactions.append(nid)
            elif nt in ["Device", "Endpoint"]:
                affected_devices.append(nid)
            elif nt in ["Server", "Domain Controller"]:
                affected_servers.append(nid)
            elif nt in ["Process", "Application", "VPN Gateway"]:
                affected_applications.append(nid)

        # Infer business process
        if affected_transactions or affected_accounts:
            business_process = "Retail Banking Payment Processing"
        elif affected_servers:
            business_process = "Core Server Network Hosting"
        elif affected_employees:
            business_process = "Internal Employee Operations"

        context = IncidentContext(
            affected_customers=list(set(affected_customers)),
            affected_employees=list(set(affected_employees)),
            affected_accounts=list(set(affected_accounts)),
            affected_transactions=list(set(affected_transactions)),
            affected_devices=list(set(affected_devices)),
            affected_servers=list(set(affected_servers)),
            affected_applications=list(set(affected_applications)),
            business_process=business_process
        )

        # 7. Investigation Context
        root_cause_candidates = []
        if sequence_output.get("entry_point"):
            root_cause_candidates.append(sequence_output.get("entry_point"))
        for rel in relationships:
            if rel.relationship_status.lower() in ["anomaly", "suspicious"]:
                root_cause_candidates.append(rel.source_node)
                root_cause_candidates.append(rel.target_node)

        impacted_entities = list(set(
            affected_customers + affected_employees + affected_accounts +
            affected_transactions + affected_devices + affected_servers
        ))

        # Build query suggestions
        queries = []
        if primary_entity:
            queries.append(f"MATCH (n)-[r]->(m) WHERE n.node_id = '{primary_entity}' RETURN n, r, m")
        for node in nodes[:2]:
            queries.append(f"MATCH (n)-[r]->(m) WHERE n.node_id = '{node.node_id}' RETURN n, r, m")

        # Similarity metrics based on shared nodes/patterns
        sim_score = 0.1
        if len(patterns) > 1:
            sim_score += 0.35
        if evidence_output.get("IOC_matches") or evidence_output.get("malware_matches"):
            sim_score += 0.4

        investigation = InvestigationContext(
            root_cause_candidates=list(set(root_cause_candidates)),
            first_observed_event=start_time,
            latest_event=end_time,
            impacted_entities=impacted_entities,
            recommended_next_queries=queries,
            related_incidents=[],
            historical_similarity=round(min(1.0, sim_score), 2)
        )

        # 9. Referenced Security Graph Events
        ref_events = []
        for ev in events:
            ref = ReferencedSecurityGraphEvent(
                event_uuid=ev.event_context.event_uuid,
                graph_node_ids=[n.node_id for n in ev.graph_nodes],
                relationship_ids=[r.relationship_id for r in ev.graph_relationships],
                path_ids=[p.path_id for p in ev.graph_paths]
            )
            ref_events.append(ref)

        return CorrelatedSecurityIncident(
            incident_info=info,
            incident_timeline=sequence_output.get("timeline_steps", []),
            correlated_evidence=evidence,
            attack_graph=attack_graph,
            ai_reasoning=reasoning,
            threat_hypotheses=hypotheses,
            confidence_assessment=confidence,
            incident_context=context,
            investigation_context=investigation,
            referenced_security_graph_events=ref_events
        )
