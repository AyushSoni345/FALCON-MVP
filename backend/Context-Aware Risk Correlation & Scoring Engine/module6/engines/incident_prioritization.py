from typing import Dict, Any, Tuple
from module6.interfaces import IPrioritizationEngine
from module6.schemas.unified_risk_assessment import ContextEvaluation
from module6.config.manager import ConfigurationManager

class IncidentPrioritizationEngine(IPrioritizationEngine):
    def __init__(self, config_manager: ConfigurationManager):
        self.config_manager = config_manager

    def evaluate_priority(self, unified_score: float, context: ContextEvaluation, suppressed: bool) -> Tuple[str, Dict[str, Any]]:
        if suppressed:
            trace = {"suppressed": True, "reason": "Incident is suppressed, downgraded to P4."}
            return "P4", trace

        thresholds = self.config_manager.get_config("priority_thresholds").thresholds
        business_crit = context.business_context.business_criticality
        
        trace_log = {"business_criticality": business_crit, "score": unified_score}

        p1_cfg = thresholds["p1"]
        if unified_score >= p1_cfg.min_score:
            if not p1_cfg.required_business_criticality or business_crit in p1_cfg.required_business_criticality:
                return "P1", trace_log

        p2_cfg = thresholds["p2"]
        if unified_score >= p2_cfg.min_score:
            if not p2_cfg.required_business_criticality or business_crit in p2_cfg.required_business_criticality:
                return "P2", trace_log
                
        p3_cfg = thresholds["p3"]
        if unified_score >= p3_cfg.min_score:
            return "P3", trace_log

        return "P4", trace_log
