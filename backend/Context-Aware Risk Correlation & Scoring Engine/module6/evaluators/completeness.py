from typing import Dict, Any

class ContextCompletenessValidator:
    REQUIRED_KEYS = [
        "business_criticality", "business_process", "service_impact",
        "asset_criticality", "asset_type", "production_system",
        "customer_segment", "customer_risk_profile", 
        "transaction_value", "payment_channel",
        "data_classification"
    ]

    def calculate_completeness(self, raw_context: Dict[str, Any]) -> float:
        """Calculates completeness score (0.0 to 1.0) based on presence of key fields in raw_context."""
        if not raw_context:
            return 0.0
            
        found = 0
        for key in self.REQUIRED_KEYS:
            val = raw_context.get(key)
            if val is not None and val != "" and val != "Unknown":
                found += 1
                
        return float(found) / len(self.REQUIRED_KEYS)
