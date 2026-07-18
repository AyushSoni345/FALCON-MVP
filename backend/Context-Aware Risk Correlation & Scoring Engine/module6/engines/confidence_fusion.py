from typing import Dict, Any, Tuple
from module6.interfaces import IConfidenceFusion
from module6.config.manager import ConfigurationManager

class ConfidenceFusionEngine(IConfidenceFusion):
    def __init__(self, config_manager: ConfigurationManager):
        self.config_manager = config_manager

    def calculate_confidence(self, ai_confidence: float, context_completeness: float, active_domains: Dict[str, Any]) -> Tuple[float, Dict[str, Any]]:
        conf_weights = self.config_manager.get_config("confidence_weights").weights
        
        w_ai = conf_weights.get("ai_confidence", 0.4)
        w_bus = conf_weights.get("business_context_confidence", 0.3)
        w_ev = conf_weights.get("evidence_strength", 0.3)
        
        # Calculate Evidence Strength (C_ev)
        num_domains = len(active_domains)
        evidence_strength = min(1.0, 0.4 + (0.3 * (num_domains - 1)))
        
        overall_confidence = (w_ai * ai_confidence) + (w_bus * context_completeness) + (w_ev * evidence_strength)
        overall_confidence = max(0.0, min(1.0, overall_confidence))
        
        trace = {
            "weights": {"ai": w_ai, "business": w_bus, "evidence": w_ev},
            "components": {
                "ai_confidence": ai_confidence,
                "business_context_confidence": context_completeness,
                "evidence_strength": evidence_strength
            },
            "overall_confidence": overall_confidence
        }
        
        return overall_confidence, trace
