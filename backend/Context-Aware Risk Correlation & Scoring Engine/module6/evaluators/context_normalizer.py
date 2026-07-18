from typing import Dict, Any
from module6.interfaces import IContextNormalizer

class ContextNormalizer(IContextNormalizer):
    def normalize(self, raw_context: Dict[str, Any]) -> Dict[str, Any]:
        normalized = dict(raw_context)

        # Normalize Customer Segment
        segment = str(normalized.get("customer_segment", "")).strip().upper()
        if segment in ["VIP", "HNW", "HIGH_NET_WORTH", "HIGH NET WORTH"]:
            normalized["customer_segment"] = "VIP"
            normalized["high_net_worth_customer"] = True
        elif segment in ["CORP", "CORPORATE", "ENTERPRISE", "B2B"]:
            normalized["customer_segment"] = "Corporate"
        elif segment:
            normalized["customer_segment"] = "Retail"
        else:
            normalized["customer_segment"] = "Unknown"

        # Normalize Business Process
        proc = str(normalized.get("business_process", "")).strip().lower()
        if any(x in proc for x in ["core", "ledger"]):
            normalized["business_process"] = "Core Banking"
        elif any(x in proc for x in ["pay", "gate", "transaction engine"]):
            normalized["business_process"] = "Payment Gateway"
        elif "atm" in proc:
            normalized["business_process"] = "ATM Network"
        elif any(x in proc for x in ["test", "sandbox", "lab"]):
            normalized["business_process"] = "Internal Test Environment"
        else:
            normalized["business_process"] = "Unknown"

        # Normalize booleans
        for bool_key in ["production_system", "vulnerable_customer", "high_net_worth_customer", 
                         "pii_exposure", "credential_exposure", "cryptographic_asset"]:
            val = normalized.get(bool_key, False)
            if isinstance(val, str):
                normalized[bool_key] = val.lower() in ["true", "1", "yes", "y", "t"]
            else:
                normalized[bool_key] = bool(val)
                
        # Fill defaults for numerics if missing
        normalized.setdefault("transaction_value", 0.0)
        normalized.setdefault("financial_exposure", 0.0)

        # Ensure valid strings for remaining categorical data
        normalized.setdefault("business_criticality", "Medium")
        normalized.setdefault("service_impact", "Medium")
        normalized.setdefault("asset_criticality", "Medium")
        normalized.setdefault("asset_type", "Unknown")
        normalized.setdefault("customer_risk_profile", "Medium")
        normalized.setdefault("transaction_frequency", "Medium")
        normalized.setdefault("payment_channel", "Unknown")
        normalized.setdefault("data_classification", "Public")
        
        return normalized
