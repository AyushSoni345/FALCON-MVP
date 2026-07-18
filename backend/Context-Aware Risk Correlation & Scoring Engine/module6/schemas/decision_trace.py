from typing import Dict, List, Any
from pydantic import BaseModel

class DecisionTrace(BaseModel):
    trace_id: str
    idempotency_key: str
    input_assessment_id: str
    incident_id: str
    timestamp: str
    config_version: str
    rule_version: str
    active_domain_scores: Dict[str, float]
    context_values_loaded: Dict[str, Any]
    rule_evaluations: List[Dict[str, Any]]
    weight_adjustments_applied: List[Dict[str, Any]]
    suppression_decisions: Dict[str, Any]
    confidence_fusion_steps: Dict[str, Any]
    final_score_calculation: Dict[str, Any]
    priority_assignment: Dict[str, Any]
