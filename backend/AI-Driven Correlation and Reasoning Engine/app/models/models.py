from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, model_validator

# =====================================================================
# SECURITY GRAPH EVENT (INPUT MODELS)
# =====================================================================

class EventContext(BaseModel):
    event_uuid: str = Field(..., description="Unique identifier for the event")
    correlation_id: str = Field(..., description="Correlation grouping identifier")
    event_type: str = Field(default="Unknown", description="Type of event")
    event_category: str = Field(default="Cyber", description="Category (Cyber, Financial, etc.)")
    normalized_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), alias="timestamp", description="Chronologically synchronized timestamp")
    source_system: str = Field(default="Unknown", description="Originating monitoring system")

    @model_validator(mode='before')
    @classmethod
    def preprocess_context(cls, data: Any) -> Any:
        if isinstance(data, dict):
            ts = data.get("timestamp") or data.get("normalized_timestamp")
            if ts == "" or ts is None:
                data["timestamp"] = datetime.now(timezone.utc)
        return data

    model_config = {
        "populate_by_name": True
    }

class GraphNode(BaseModel):
    node_id: str = Field(..., description="Unique node identifier")
    node_type: str = Field(..., description="Type of entity, e.g., Device, IP, Customer")
    properties: Dict[str, Any] = Field(default_factory=dict, alias="attributes", description="Metadata properties of the node")

    model_config = {
        "populate_by_name": True
    }

class GraphRelationship(BaseModel):
    relationship_id: str = Field(..., description="Unique relationship identifier")
    relationship_type: str = Field(..., description="Type of relationship, e.g., LOGGED_IN_FROM")
    source_node: str = Field(..., alias="source_node_id", description="Source Node ID")
    target_node: str = Field(..., alias="target_node_id", description="Target Node ID")
    timestamp: datetime = Field(..., alias="last_seen", description="Timestamp of the relationship activation")
    confidence: float = Field(default=1.0, description="Confidence of relationship extraction")
    relationship_status: str = Field(default="Active", description="State or status of the relationship")

    model_config = {
        "populate_by_name": True
    }

class GraphPath(BaseModel):
    path_id: str = Field(..., description="Unique path identifier")
    path_nodes: List[str] = Field(..., alias="ordered_nodes", description="Ordered list of Node IDs in the path")
    path_length: int = Field(..., description="Length of the path (number of edges)")
    path_type: str = Field(..., description="Type or classification of the path")
    confidence: float = Field(default=1.0, description="Confidence of the path")

    model_config = {
        "populate_by_name": True
    }

class GraphMetrics(BaseModel):
    node_degree: Dict[str, int] = Field(default_factory=dict, description="Degrees of relevant nodes")
    relationship_count: int = Field(default=0, alias="total_edges", description="Total relationships in partition")
    neighbor_count: Dict[str, int] = Field(default_factory=dict, description="Neighbor count of nodes")
    graph_depth: int = Field(default=1, description="Depth of traversed subgraph")
    connected_components: int = Field(default=1, description="Number of connected components")
    shortest_path_to_customer: Optional[int] = Field(None, description="Shortest hop count to customer node")
    shortest_path_to_transaction: Optional[int] = Field(None, description="Shortest hop count to transaction node")
    shortest_path_to_endpoint: Optional[int] = Field(None, description="Shortest hop count to endpoint node")

    model_config = {
        "populate_by_name": True
    }

class GraphContext(BaseModel):
    primary_entity: str = Field(default="Unknown", description="Main entity under analysis")
    related_entities: List[str] = Field(default_factory=list, description="Entities related via graph edges")
    active_sessions: List[str] = Field(default_factory=list, description="Associated active session identifiers")
    linked_transactions: List[str] = Field(default_factory=list, description="Associated transaction IDs")
    linked_devices: List[str] = Field(default_factory=list, description="Associated device IDs")
    linked_ips: List[str] = Field(default_factory=list, description="Associated IP addresses")
    linked_beneficiaries: List[str] = Field(default_factory=list, description="Associated beneficiary identifiers")
    linked_alerts: List[str] = Field(default_factory=list, description="Correlated SIEM/security alerts")
    previous_events: List[str] = Field(default_factory=list, description="List of previous related event IDs")

    @model_validator(mode='before')
    @classmethod
    def preprocess_context(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "primary_entity" not in data and "primary_entities" in data:
                entities = data["primary_entities"]
                if isinstance(entities, list):
                    extracted = []
                    for e in entities:
                        if isinstance(e, dict):
                            extracted.append(e.get("node_id") or e.get("id") or str(e))
                        else:
                            extracted.append(str(e))
                    data["primary_entity"] = extracted[0] if extracted else "Unknown"
                else:
                    data["primary_entity"] = str(entities) if entities else "Unknown"

            if "related_entities" in data:
                rel_ent = data["related_entities"]
                if isinstance(rel_ent, list):
                    mapped = []
                    for item in rel_ent:
                        if isinstance(item, dict):
                            mapped.append(item.get("node_id") or item.get("id") or str(item))
                        else:
                            mapped.append(str(item))
                    data["related_entities"] = mapped
        return data

    model_config = {
        "populate_by_name": True
    }

class GraphStateMetadata(BaseModel):
    graph_version: str = Field(default="v1.0", description="Version of the security graph")
    node_created: int = Field(default=0, description="Nodes created in this step")
    node_updated: int = Field(default=0, description="Nodes updated in this step")
    relationships_added: int = Field(default=0, description="Relationships added in this step")
    relationships_updated: int = Field(default=0, description="Relationships updated in this step")
    graph_timestamp: datetime = Field(default_factory=datetime.now, alias="last_update_timestamp", description="Timestamp of graph state snapshot")
    graph_partition: str = Field(default="partition-1", description="Partition key of graph db")
    graph_status: str = Field(default="Active", description="Status of the graph state")

    model_config = {
        "populate_by_name": True
    }

class ContextEnrichedEvent(BaseModel):
    original_event: Dict[str, Any] = Field(default_factory=dict, description="Raw normalized event from Module 2")

class SecurityGraphEvent(BaseModel):
    event_context: EventContext = Field(..., alias="Event Context", description="Event context metadata")
    graph_nodes: List[GraphNode] = Field(..., alias="Graph Nodes", description="List of graph nodes")
    graph_relationships: List[GraphRelationship] = Field(..., alias="Graph Relationships", description="List of graph relationships")
    graph_paths: List[GraphPath] = Field(..., alias="Graph Paths", description="List of graph paths")
    graph_metrics: GraphMetrics = Field(..., alias="Graph Metrics", description="Metrics associated with the graph state")
    graph_context: GraphContext = Field(..., alias="Graph Context", description="Contextual entity summaries")
    graph_state_metadata: GraphStateMetadata = Field(..., alias="Graph State Metadata", description="State metadata from Module 3")
    context_enriched_event: ContextEnrichedEvent = Field(..., alias="Context Enriched Event", description="Context enriched event mapping")

    @model_validator(mode='before')
    @classmethod
    def preprocess_event(cls, data: Any) -> Any:
        if isinstance(data, dict):
            ctx_key = "Event Context" if "Event Context" in data else "event_context"
            context = data.get(ctx_key)
            
            # If context is a Pydantic model instead of a dict, extract dict
            if hasattr(context, "model_dump"):
                context = context.model_dump()
                data[ctx_key] = context
            elif not isinstance(context, dict):
                context = {}
                data[ctx_key] = context

            corr_id = context.get("correlation_id")
            evt_type = context.get("event_type")
            src_sys = context.get("source_system")
            ts = context.get("timestamp") or context.get("normalized_timestamp")

            enriched_key = "Context Enriched Event" if "Context Enriched Event" in data else "context_enriched_event"
            enriched = data.get(enriched_key)
            orig = None
            if isinstance(enriched, dict):
                orig = enriched.get("original_event") or enriched.get("event_information")
            elif hasattr(enriched, "original_event"):
                orig = getattr(enriched, "original_event") or getattr(enriched, "event_information", None)
            elif hasattr(enriched, "event_information"):
                orig = getattr(enriched, "event_information")

            if hasattr(orig, "model_dump"):
                orig = orig.model_dump()

            if isinstance(orig, dict):
                meta = orig.get("metadata") if "metadata" in orig else orig
                if isinstance(meta, dict):
                    if not corr_id or corr_id == "":
                        corr_id = meta.get("correlation_id")
                    if not evt_type or evt_type == "":
                        evt_type = meta.get("event_type")
                    if not src_sys or src_sys == "":
                        src_sys = meta.get("source_system")
                    if not ts or ts == "":
                        ts = meta.get("original_timestamp") or meta.get("ingestion_timestamp") or meta.get("normalized_timestamp")

            if not corr_id or corr_id == "":
                gctx_key = "Graph Context" if "Graph Context" in data else "graph_context"
                gctx = data.get(gctx_key) or {}
                prim = "Unknown"
                if isinstance(gctx, dict):
                    prim = gctx.get("primary_entity") or "Unknown"
                elif hasattr(gctx, "primary_entity"):
                    prim = getattr(gctx, "primary_entity") or "Unknown"
                corr_id = f"CORR-{prim}"

            if not evt_type or evt_type == "":
                evt_type = "Unknown"
            if not src_sys or src_sys == "":
                src_sys = "Unknown"

            context["correlation_id"] = corr_id
            context["event_type"] = evt_type
            context["source_system"] = src_sys
            context["timestamp"] = ts or datetime.now(timezone.utc)

        return data

    model_config = {
        "populate_by_name": True
    }

# =====================================================================
# CORRELATED SECURITY INCIDENT (OUTPUT MODELS)
# =====================================================================

class IncidentInformation(BaseModel):
    incident_id: str = Field(..., description="Unique generated incident ID")
    incident_type: str = Field(..., description="Classification of the incident (e.g. Account Takeover)")
    incident_category: str = Field(..., description="Category (Cyber, Financial, Hybrid, Quantum)")
    incident_status: str = Field(..., description="Lifecycle status (Active, Contained, Closed)")
    incident_start_time: datetime = Field(..., description="Start timestamp of first event")
    incident_end_time: datetime = Field(..., description="End timestamp of last event")
    incident_duration: float = Field(..., description="Duration in seconds")
    primary_entity: str = Field(..., description="Primary entity implicated")
    affected_assets: int = Field(..., description="Count of distinct assets/entities impacted")
    correlated_event_count: int = Field(..., description="Total correlated events")

class TimelineStep(BaseModel):
    sequence_number: int = Field(..., description="Step sequence in chronological order")
    timestamp: datetime = Field(..., description="Event timestamp")
    event_uuid: str = Field(..., description="Originating event UUID")
    action: str = Field(..., description="Action taken, e.g. LOGIN")
    entity: str = Field(..., description="Implicated entity")
    confidence: float = Field(..., description="Confidence score of step extraction")

class CorrelatedEvidence(BaseModel):
    related_events: List[str] = Field(default_factory=list, description="Referenced Event UUIDs")
    graph_paths: List[str] = Field(default_factory=list, description="Referenced Path IDs")
    graph_nodes: List[str] = Field(default_factory=list, description="Referenced Node IDs")
    graph_relationships: List[str] = Field(default_factory=list, description="Referenced Relationship IDs")
    IOC_matches: List[str] = Field(default_factory=list, description="Indicators of Compromise matched")
    malware_matches: List[str] = Field(default_factory=list, description="Malware families matched")
    fraud_matches: List[str] = Field(default_factory=list, description="Fraud indicators matched")
    behavioral_anomalies: List[str] = Field(default_factory=list, description="Identified behavioral anomalies")
    supporting_logs: List[str] = Field(default_factory=list, description="Supporting log metadata strings")

class AttackGraph(BaseModel):
    attack_nodes: List[GraphNode] = Field(default_factory=list, description="Nodes in the incident subgraph")
    attack_relationships: List[GraphRelationship] = Field(default_factory=list, description="Edges in the incident subgraph")
    attack_paths: List[GraphPath] = Field(default_factory=list, description="Key attack paths traversed")
    attack_entry_point: str = Field(..., description="Identified entry point node/IP")
    attack_exit_point: str = Field(..., description="Identified exit point or final objective node")
    lateral_movements: List[str] = Field(default_factory=list, description="Summary descriptions of lateral movements")

class AIReasoning(BaseModel):
    reasoning_chain: List[str] = Field(..., description="Sequential reasoning steps taken by the AI")
    supporting_patterns: List[str] = Field(..., description="Patterns recognized (e.g. Credential Theft)")
    graph_observations: List[str] = Field(..., description="Inferred facts from graph topology")
    temporal_observations: List[str] = Field(..., description="Inferred facts from event timings")
    anomaly_summary: str = Field(..., description="Text summary of overall anomalies")
    relationship_summary: str = Field(..., description="Text summary of graph connections")

class ThreatHypothesis(BaseModel):
    hypothesis_id: str = Field(..., description="Unique hypothesis identifier")
    hypothesis_type: str = Field(..., description="Type of hypothesis (e.g., Credential Theft, False Positive)")
    description: str = Field(..., description="Human-readable description of potential scenario")
    supporting_evidence: List[str] = Field(..., description="List of evidence IDs supporting this scenario")
    contradictory_evidence: List[str] = Field(..., description="List of evidence IDs contradicting this scenario")
    likelihood: float = Field(..., description="Estimated probability/likelihood (0.0 to 1.0)")

class ConfidenceAssessment(BaseModel):
    overall_confidence: float = Field(..., description="Cumulative confidence score")
    temporal_confidence: float = Field(..., description="Confidence based on timing/chronology")
    graph_confidence: float = Field(..., description="Confidence based on graph connections/degree")
    behavioral_confidence: float = Field(..., description="Confidence based on behavioral anomalies")
    threat_intelligence_confidence: float = Field(..., description="Confidence based on external threat feeds")
    fraud_confidence: float = Field(..., description="Confidence based on fraud indicators")
    evidence_score: float = Field(..., description="Quality score of available evidence")
    uncertainty_score: float = Field(..., description="Uncertainty score reflecting gaps in data")

class IncidentContext(BaseModel):
    affected_customers: List[str] = Field(default_factory=list, description="List of affected customer identifiers")
    affected_employees: List[str] = Field(default_factory=list, description="List of affected employee identifiers")
    affected_accounts: List[str] = Field(default_factory=list, description="List of affected financial accounts")
    affected_transactions: List[str] = Field(default_factory=list, description="List of affected transactions")
    affected_devices: List[str] = Field(default_factory=list, description="List of affected device identifiers")
    affected_servers: List[str] = Field(default_factory=list, description="List of affected server hosts")
    affected_applications: List[str] = Field(default_factory=list, description="List of affected application names")
    business_process: str = Field(..., description="Identifier or name of impacted business process")

class InvestigationContext(BaseModel):
    root_cause_candidates: List[str] = Field(default_factory=list, description="Potential root cause elements")
    first_observed_event: datetime = Field(..., description="Timestamp of first observed event")
    latest_event: datetime = Field(..., description="Timestamp of most recent event")
    impacted_entities: List[str] = Field(default_factory=list, description="Entities impacted by this incident")
    recommended_next_queries: List[str] = Field(default_factory=list, description="Recommended graph queries for investigation")
    related_incidents: List[str] = Field(default_factory=list, description="Identifiers of related incidents")
    historical_similarity: float = Field(..., description="Calculated similarity score to historical incidents")

class ReferencedSecurityGraphEvent(BaseModel):
    event_uuid: str = Field(..., description="UUID of the referenced event")
    graph_node_ids: List[str] = Field(default_factory=list, description="IDs of graph nodes in this event")
    relationship_ids: List[str] = Field(default_factory=list, description="IDs of relationships in this event")
    path_ids: List[str] = Field(default_factory=list, description="IDs of paths in this event")

class CorrelatedSecurityIncident(BaseModel):
    incident_info: IncidentInformation = Field(..., description="Incident identity and metadata")
    incident_timeline: List[TimelineStep] = Field(..., description="Reconstructed chronological sequence")
    correlated_evidence: CorrelatedEvidence = Field(..., description="Correlated supporting evidence items")
    attack_graph: AttackGraph = Field(..., description="Incident-specific attack graph layout")
    ai_reasoning: AIReasoning = Field(..., description="Reasoning and patterns evaluated")
    threat_hypotheses: List[ThreatHypothesis] = Field(..., description="Competing threat hypotheses")
    confidence_assessment: ConfidenceAssessment = Field(..., description="Multi-dimensional confidence scores")
    incident_context: IncidentContext = Field(..., description="Business and asset context")
    investigation_context: InvestigationContext = Field(..., description="SOC and investigation workflow data")
    referenced_security_graph_events: List[ReferencedSecurityGraphEvent] = Field(..., description="References to the source events used in correlation")
