from app.generators.base import BaseGenerator
from app.models.requests import UnifiedRiskAssessment
from app.models.responses import InvestigationGuidance

class InvestigationGuidanceEngine(BaseGenerator):
    """Generates the Investigation Guidance section of the report."""

    def generate(self, assessment: UnifiedRiskAssessment) -> InvestigationGuidance:
        info = assessment.assessment_information
        eval_sec = assessment.context_evaluation

        recommended_steps = [
            f"Review transaction authorization logs for payment channel '{eval_sec.transaction_context.payment_channel}' during the identified incident window.",
            f"Inspect host authorization telemetry for production system '{eval_sec.asset_context.production_system}' to identify potentially compromised sessions.",
            f"Correlate customer risk profile '{eval_sec.customer_context.customer_risk_profile}' with historical transaction frequencies for segment '{eval_sec.customer_context.customer_segment}'.",
            f"Verify credential exposure records matching type '{eval_sec.data_context.credential_exposure}' against recent login attempts."
        ]

        priority_artifacts = [
            f"Transaction logs and transmission payloads on payment channel '{eval_sec.transaction_context.payment_channel}'",
            f"System access and session events for production host '{eval_sec.asset_context.production_system}'",
            f"Cryptographic key authorization histories for asset '{eval_sec.data_context.cryptographic_asset}'"
        ]

        additional_queries = [
            f"Query historical session durations for customer segment '{eval_sec.customer_context.customer_segment}'",
            f"Retrieve active login sessions matching credential exposure classification '{eval_sec.data_context.credential_exposure}'"
        ]

        related_entities = [
            f"Cryptographic Key Archive: {eval_sec.data_context.cryptographic_asset}",
            f"Production Endpoint Host: {eval_sec.asset_context.production_system}",
            f"Customer Risk Segment: {eval_sec.customer_context.customer_segment}"
        ]

        recommended_validation = [
            "Initiate multi-factor identity challenge sequence for the primary account owner",
            f"Conduct secure customer verification check using procedures defined for segment '{eval_sec.customer_context.customer_segment}'"
        ]

        return InvestigationGuidance(
            recommended_investigation_steps=self.formatter.format_list_to_bullets(recommended_steps),
            priority_artifacts=self.formatter.format_list_to_bullets(priority_artifacts),
            additional_queries=self.formatter.format_list_to_bullets(additional_queries),
            related_entities=self.formatter.format_list_to_bullets(related_entities),
            recommended_validation=self.formatter.format_list_to_bullets(recommended_validation)
        )
