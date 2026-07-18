from typing import Dict, Any, Tuple
from module6.interfaces import IContextEvaluator
from module6.schemas.unified_risk_assessment import (
    ContextEvaluation, BusinessContext, AssetContext, CustomerContext, 
    TransactionContext, DataContext
)
from .completeness import ContextCompletenessValidator

class ContextEvaluator(IContextEvaluator):
    def __init__(self):
        self.completeness_validator = ContextCompletenessValidator()

    def evaluate(self, normalized_context: Dict[str, Any]) -> Tuple[ContextEvaluation, float]:
        # Measure completeness based on the normalized context (which has some defaults but 'Unknown's can be tracked)
        completeness_score = self.completeness_validator.calculate_completeness(normalized_context)
        
        evaluation = ContextEvaluation(
            business_context=BusinessContext(
                business_criticality=normalized_context["business_criticality"],
                business_process=normalized_context["business_process"],
                service_impact=normalized_context["service_impact"]
            ),
            asset_context=AssetContext(
                asset_criticality=normalized_context["asset_criticality"],
                asset_type=normalized_context["asset_type"],
                production_system=normalized_context["production_system"]
            ),
            customer_context=CustomerContext(
                customer_segment=normalized_context["customer_segment"],
                customer_risk_profile=normalized_context["customer_risk_profile"],
                vulnerable_customer=normalized_context["vulnerable_customer"],
                high_net_worth_customer=normalized_context["high_net_worth_customer"]
            ),
            transaction_context=TransactionContext(
                transaction_value=normalized_context["transaction_value"],
                transaction_frequency=normalized_context["transaction_frequency"],
                payment_channel=normalized_context["payment_channel"],
                financial_exposure=normalized_context["financial_exposure"]
            ),
            data_context=DataContext(
                data_classification=normalized_context["data_classification"],
                pii_exposure=normalized_context["pii_exposure"],
                credential_exposure=normalized_context["credential_exposure"],
                cryptographic_asset=normalized_context["cryptographic_asset"]
            )
        )
        return evaluation, completeness_score
