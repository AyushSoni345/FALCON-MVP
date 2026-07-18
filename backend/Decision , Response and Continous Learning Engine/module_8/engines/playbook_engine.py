from typing import Dict, Any
from module_8.models.input_models import ExplainableThreatReport
from module_8.models.output_models import IncidentResponsePlan, ResponseExecutionPlan, ResponseDecisionTrace

class PlaybookEngine:
    def generate_plans(self, etr: ExplainableThreatReport, matched_rule: Dict[str, Any]) -> (IncidentResponsePlan, ResponseExecutionPlan):
        
        # Build the decision trace factors
        decision_factors = []
        if etr.executive_summary.risk_level:
            decision_factors.append(f"Risk Level: {etr.executive_summary.risk_level}")
        if etr.executive_summary.recommended_priority:
            decision_factors.append(f"Priority: {etr.executive_summary.recommended_priority}")
        if etr.root_cause_analysis.probable_root_cause:
            decision_factors.append(f"Root Cause: {etr.root_cause_analysis.probable_root_cause}")
        if etr.root_cause_analysis.confidence is not None:
            decision_factors.append(f"Confidence: {etr.root_cause_analysis.confidence * 100}%")
            
        decision_trace = ResponseDecisionTrace(
            decision_factors=decision_factors,
            selected_rule=matched_rule.get("rule_name", "Default Fallback Rule")
        )
        
        response_plan = IncidentResponsePlan(
            incident_type=etr.referenced_unified_risk_assessment.incident_classification,
            response_strategy=matched_rule.get("strategy", "Unknown"),
            recommended_actions=matched_rule.get("recommended_actions", []),
            business_justification=matched_rule.get("business_justification", ""),
            expected_outcome=matched_rule.get("expected_outcome", ""),
            response_decision_trace=decision_trace
        )
        
        execution_plan = ResponseExecutionPlan(
            action_sequence=matched_rule.get("recommended_actions", []),
            execution_type=matched_rule.get("execution_type", "Manual"),
            assigned_team=matched_rule.get("assigned_team", "Triage"),
            execution_priority=etr.executive_summary.recommended_priority,
            estimated_completion_time="4 hours" # could be dynamic in a fully fleshed system
        )
        
        return response_plan, execution_plan
