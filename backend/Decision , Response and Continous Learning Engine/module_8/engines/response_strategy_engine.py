from typing import Dict, Any, Optional
from module_8.models.input_models import ExplainableThreatReport
from module_8.config import load_rules
from module_8.utils.logger import get_logger

logger = get_logger(__name__)

class ResponseStrategyEngine:
    def __init__(self):
        self.rules = load_rules()
        
    def _matches_condition(self, condition_key: str, condition_val: Any, etr: ExplainableThreatReport) -> bool:
        if condition_key == "incident_classification":
            classification = etr.referenced_unified_risk_assessment.incident_classification
            if isinstance(condition_val, list):
                return classification in condition_val
            return classification == condition_val
            
        if condition_key == "min_unified_risk_score":
            score = etr.executive_summary.unified_risk_score
            return score is not None and score >= condition_val
            
        if condition_key == "risk_level":
            level = etr.executive_summary.risk_level
            if isinstance(condition_val, list):
                return level in condition_val
            return level == condition_val
            
        if condition_key == "min_confidence":
            conf = etr.root_cause_analysis.confidence
            return conf is not None and conf >= condition_val
            
        return False

    def _evaluate_rule(self, rule: Dict[str, Any], etr: ExplainableThreatReport) -> bool:
        conditions = rule.get("conditions", {})
        for k, v in conditions.items():
            if not self._matches_condition(k, v, etr):
                return False
        return True

    def evaluate_strategy(self, etr: ExplainableThreatReport) -> Dict[str, Any]:
        for rule in self.rules:
            if self._evaluate_rule(rule, etr):
                logger.info(f"Matched rule with strategy {rule.get('strategy')} and playbook {rule.get('playbook_name')}")
                return rule
                
        # Default fallback rule
        logger.warning("No specific rule matched. Using default strategy.")
        return {
            "strategy": "Investigation & Monitoring",
            "playbook_name": "Standard Alert Monitoring Playbook",
            "execution_type": "Manual",
            "assigned_team": "L1 Security Operations",
            "recommended_actions": [
                "Log incident to SIEM",
                "Review in next security cycle"
            ],
            "business_justification": "Default action for unclassified or low-risk anomalies.",
            "expected_outcome": "Event tracked for future reference."
        }
