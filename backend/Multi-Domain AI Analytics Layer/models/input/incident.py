from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, AliasChoices

# Replication of Module 4 structures for self-containment of Module 5

class GraphNode(BaseModel):
    node_id: str = Field(..., description="Unique node identifier")
    node_type: str = Field(..., description="Type of entity, e.g., Device, IP, Customer")
    properties: Dict[str, Any] = Field(default_factory=dict, description="Metadata properties of the node")

class GraphRelationship(BaseModel):
    relationship_id: str = Field(..., description="Unique relationship identifier")
    relationship_type: str = Field(..., description="Type of relationship, e.g., LOGGED_IN_FROM")
    source_node: str = Field(..., validation_alias=AliasChoices("source_node", "source_node_id"), description="Source Node ID")
    target_node: str = Field(..., validation_alias=AliasChoices("target_node", "target_node_id"), description="Target Node ID")
    timestamp: datetime = Field(..., validation_alias=AliasChoices("timestamp", "last_seen"), description="Timestamp of the relationship activation")
    confidence: float = Field(..., description="Confidence of relationship extraction")
    relationship_status: str = Field(..., description="State or status of the relationship")

class GraphPath(BaseModel):
    path_id: str = Field(..., description="Unique path identifier")
    path_nodes: List[str] = Field(..., validation_alias=AliasChoices("path_nodes", "ordered_nodes"), description="Ordered list of Node IDs in the path")
    path_length: int = Field(..., description="Length of the path (number of edges)")
    path_type: str = Field(..., description="Type or classification of the path")
    confidence: float = Field(..., description="Confidence of the path")

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

class PredictiveIntelligence(BaseModel):
    predictions_enabled: bool = Field(default=False, description="Flag indicating if predictive engine is active")
    predicted_next_action: Optional[str] = Field(None, description="Hypothesized next attacker step")
    predicted_target: Optional[str] = Field(None, description="Hypothesized next target asset")
    time_to_next_action_seconds: Optional[float] = Field(None, description="Predicted time horizon")
    prediction_confidence: Optional[float] = Field(None, description="Confidence of threat projection")

class CorrelatedSecurityIncident(BaseModel):
    incident_information: IncidentInformation = Field(
        ..., 
        validation_alias=AliasChoices("incident_information", "incident_info"), 
        description="Incident identity and metadata"
    )
    incident_timeline: List[TimelineStep] = Field(..., description="Reconstructed chronological sequence")
    correlated_evidence: CorrelatedEvidence = Field(..., description="Correlated supporting evidence items")
    attack_graph: AttackGraph = Field(..., description="Incident-specific attack graph layout")
    ai_reasoning: AIReasoning = Field(..., description="Reasoning and patterns evaluated")
    threat_hypotheses: List[ThreatHypothesis] = Field(..., description="Competing threat hypotheses")
    confidence_assessment: ConfidenceAssessment = Field(..., description="Multi-dimensional confidence scores")
    incident_context: IncidentContext = Field(..., description="Business and asset context")
    investigation_context: InvestigationContext = Field(..., description="SOC and investigation workflow data")
    predictive_intelligence: Optional[PredictiveIntelligence] = Field(default=None, description="Predictive next-step actions")
    referenced_security_graph_events: List[ReferencedSecurityGraphEvent] = Field(..., description="References to the source events used in correlation")
