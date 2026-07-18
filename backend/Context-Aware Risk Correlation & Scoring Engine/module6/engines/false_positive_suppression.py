from typing import Dict, Any, Tuple, Optional
from module6.interfaces import ISuppressionEngine
from module6.schemas.unified_risk_assessment import ContextEvaluation
from module6.config.manager import ConfigurationManager

class FalsePositiveSuppressionEngine(ISuppressionEngine):
    def __init__(self, config_manager: ConfigurationManager):
        self.config_manager = config_manager

    def evaluate_suppression(self, scores: Dict[str, float], context: ContextEvaluation, active_domains_count: int, correlation_strength: float) -> Tuple[bool, Optional[str], Optional[str], Dict[str, Any]]:
        suppression_config = self.config_manager.get_config("suppression_rules")
        
        # Check overrides
        overrides = suppression_config.overrides
        if overrides.prevent_on_multi_domain and active_domains_count >= overrides.min_domains_for_override:
            if correlation_strength >= overrides.min_correlation_strength:
                trace = {"override": "prevent_on_multi_domain", "active_domains": active_domains_count, "correlation": correlation_strength}
                return False, None, None, trace

        # Evaluate rules
        for rule in suppression_config.suppression_rules:
            if not rule.enabled:
                continue
            
            cond = rule.conditions
            match = True
            
            if cond.asset_type and context.asset_context.asset_type not in cond.asset_type:
                match = False
            if match and cond.production_system is not None and context.asset_context.production_system != cond.production_system:
                match = False
            if match and cond.business_process and context.business_context.business_process not in cond.business_process:
                match = False
            if match and cond.service_impact and context.business_context.service_impact not in cond.service_impact:
                match = False
            if match and cond.pii_exposure is not None and context.data_context.pii_exposure != cond.pii_exposure:
                match = False
            if match and cond.credential_exposure is not None and context.data_context.credential_exposure != cond.credential_exposure:
                match = False
                
            if match:
                trace = {
                    "rule_id": rule.rule_id,
                    "rule_name": rule.rule_name,
                    "version": rule.version,
                    "matched_conditions": cond.model_dump()
                }
                return True, rule.rule_name, rule.reason, trace

        return False, None, None, {"status": "no_rule_matched"}
