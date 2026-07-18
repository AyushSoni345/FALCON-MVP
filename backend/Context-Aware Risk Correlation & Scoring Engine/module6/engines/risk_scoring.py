from typing import Dict, Any, Tuple, List
from module6.interfaces import IRiskScoringPipeline
from module6.schemas.unified_risk_assessment import ContextEvaluation
from module6.config.manager import ConfigurationManager

class RiskScoringPipeline(IRiskScoringPipeline):
    def __init__(self, config_manager: ConfigurationManager):
        self.config_manager = config_manager

    def _calculate_domain_weight_adjustment(self, domain_name: str, domain_details: Any, context: ContextEvaluation, weight_config: Any) -> Tuple[float, List[Dict[str, Any]]]:
        adjustment = 0.0
        trace = []

        pos_adj = weight_config.positive_adjustments
        neg_adj = weight_config.negative_adjustments

        # Evaluate positive boosts
        if context.asset_context.production_system:
            val = pos_adj.get("production_system", 8.0)
            adjustment += val
            trace.append({"factor": "production_system", "adjustment": val})

        if context.business_context.business_process == "Core Banking":
            val = pos_adj.get("core_banking_process", 10.0)
            adjustment += val
            trace.append({"factor": "core_banking_process", "adjustment": val})
        elif context.business_context.business_process == "Payment Gateway":
            val = pos_adj.get("payment_gateway_process", 10.0)
            adjustment += val
            trace.append({"factor": "payment_gateway_process", "adjustment": val})

        if context.asset_context.asset_criticality == "Critical":
            val = pos_adj.get("critical_asset_criticality", 8.0)
            adjustment += val
            trace.append({"factor": "critical_asset_criticality", "adjustment": val})
        elif context.asset_context.asset_criticality == "High":
            val = pos_adj.get("high_asset_criticality", 5.0)
            adjustment += val
            trace.append({"factor": "high_asset_criticality", "adjustment": val})

        if context.customer_context.customer_segment == "VIP":
            val = pos_adj.get("vip_customer", 6.0)
            adjustment += val
            trace.append({"factor": "vip_customer", "adjustment": val})
        
        if context.customer_context.high_net_worth_customer:
            val = pos_adj.get("high_net_worth_customer", 6.0)
            adjustment += val
            trace.append({"factor": "high_net_worth_customer", "adjustment": val})

        if context.customer_context.vulnerable_customer:
            val = pos_adj.get("vulnerable_customer", 6.0)
            adjustment += val
            trace.append({"factor": "vulnerable_customer", "adjustment": val})

        if context.data_context.data_classification == "PII":
            val = pos_adj.get("pii_data_classification", 8.0)
            adjustment += val
            trace.append({"factor": "pii_data_classification", "adjustment": val})
        elif context.data_context.data_classification == "Credentials":
            val = pos_adj.get("credentials_data_classification", 10.0)
            adjustment += val
            trace.append({"factor": "credentials_data_classification", "adjustment": val})
        elif context.data_context.data_classification == "Keys":
            val = pos_adj.get("keys_data_classification", 10.0)
            adjustment += val
            trace.append({"factor": "keys_data_classification", "adjustment": val})

        if context.transaction_context.transaction_value > 50000.0:
            val = pos_adj.get("high_value_transaction", 8.0)
            adjustment += val
            trace.append({"factor": "high_value_transaction", "adjustment": val})

        if context.transaction_context.financial_exposure > 50000.0:
            val = pos_adj.get("high_financial_exposure", 8.0)
            adjustment += val
            trace.append({"factor": "high_financial_exposure", "adjustment": val})

        if getattr(domain_details, 'confidence', 0.0) >= 0.85:
            val = pos_adj.get("high_ai_confidence", 5.0)
            adjustment += val
            trace.append({"factor": "high_ai_confidence", "adjustment": val})

        # Evaluate negative suppressions
        if context.business_context.business_process == "Internal Test Environment":
            val = neg_adj.get("internal_test_environment", -15.0)
            adjustment += val
            trace.append({"factor": "internal_test_environment", "adjustment": val})

        if context.asset_context.asset_type == "Development Server":
            val = neg_adj.get("development_server", -15.0)
            adjustment += val
            trace.append({"factor": "development_server", "adjustment": val})
        elif context.asset_context.asset_type == "lab server":
            val = neg_adj.get("lab_server", -15.0)
            adjustment += val
            trace.append({"factor": "lab_server", "adjustment": val})
        elif context.asset_context.asset_type == "Sandbox":
            val = neg_adj.get("sandbox", -15.0)
            adjustment += val
            trace.append({"factor": "sandbox", "adjustment": val})

        if not context.asset_context.production_system:
            val = neg_adj.get("non_production_system", -10.0)
            adjustment += val
            trace.append({"factor": "non_production_system", "adjustment": val})

        if 0.0 < context.transaction_context.transaction_value < 100.0:
            val = neg_adj.get("low_value_transaction", -5.0)
            adjustment += val
            trace.append({"factor": "low_value_transaction", "adjustment": val})

        if context.business_context.service_impact == "None":
            val = neg_adj.get("no_service_impact", -8.0)
            adjustment += val
            trace.append({"factor": "no_service_impact", "adjustment": val})

        if getattr(domain_details, 'confidence', 0.0) < 0.4:
            val = neg_adj.get("weak_ai_evidence", -10.0)
            adjustment += val
            trace.append({"factor": "weak_ai_evidence", "adjustment": val})

        return adjustment, trace

    def calculate_scores(self, active_domains: Dict[str, Any], context: ContextEvaluation) -> Tuple[Dict[str, float], float, Dict[str, Any]]:
        weight_config = self.config_manager.get_config("risk_weights")
        scoring_formula = self.config_manager.get_config("scoring_formula")
        
        weighted_scores = {}
        adjustments_applied = []
        max_score = 0.0
        high_risk_count = 0

        for domain_name, details in active_domains.items():
            base_score = details.domain_score
            adjustment, trace = self._calculate_domain_weight_adjustment(domain_name, details, context, weight_config)
            
            # Cap at 0 and 100
            adjusted_score = max(0.0, min(100.0, base_score + adjustment))
            weighted_scores[domain_name] = adjusted_score
            adjustments_applied.append({"domain": domain_name, "base_score": base_score, "adjustment": adjustment, "factors": trace})
            
            if adjusted_score > max_score:
                max_score = adjusted_score
            if adjusted_score >= scoring_formula.multi_domain_threshold:
                high_risk_count += 1

        # Apply multi-domain boost
        correlation_boost = 0.0
        if high_risk_count >= 2:
            correlation_boost = min(
                scoring_formula.max_boost, 
                scoring_formula.multi_domain_boost_factor * (high_risk_count - 1)
            )

        unified_score = max(0.0, min(100.0, max_score + correlation_boost))

        trace_log = {
            "adjustments_applied": adjustments_applied,
            "max_score": max_score,
            "correlation_boost": correlation_boost,
            "unified_score": unified_score
        }

        return weighted_scores, unified_score, trace_log
