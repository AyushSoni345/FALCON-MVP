from app.generators.base import BaseGenerator
from app.models.requests import UnifiedRiskAssessment
from app.models.responses import IncidentNarrative

class IncidentNarrativeBuilder(BaseGenerator):
    """Builds the Incident Narrative section of the report."""

    def generate(self, assessment: UnifiedRiskAssessment) -> IncidentNarrative:
        info = assessment.assessment_information
        eval_sec = assessment.context_evaluation
        classification = assessment.incident_classification
        ref_m5 = assessment.referenced_domain_ai_assessment

        # Resolve active domains list
        active_domains = []
        if isinstance(ref_m5.active_domain_assessments, list):
            active_domains = ref_m5.active_domain_assessments
        else:
            act = ref_m5.active_domain_assessments
            if act:
                if getattr(act, "behaviour_assessment", None): active_domains.append("Behaviour")
                if getattr(act, "fraud_assessment", None): active_domains.append("Fraud")
                if getattr(act, "cyber_assessment", None): active_domains.append("Cyber")
                if getattr(act, "quantum_assessment", None): active_domains.append("Quantum")
        sorted_domains = sorted(active_domains)

        # 1. Narrative Summary
        narrative_summary = self.templates.get_narrative_summary(
            classification=classification.final_incident_type,
            primary_entity=info.primary_entity,
            start_time=self.formatter.format_timestamp(info.incident_start_time),
            duration=info.incident_duration,
            assets_count=info.affected_assets
        )

        # 2. Attack Progression paragraphs
        timeline_summary = " -> ".join(sorted_domains)
        entry_action = sorted_domains[0] if sorted_domains else "Unspecified Event"

        progression_para = self.templates.get_narrative_progression(
            primary_entity=info.primary_entity,
            entry_action=entry_action,
            entry_point=eval_sec.transaction_context.payment_channel,
            timeline_summary=timeline_summary,
            end_time=self.formatter.format_timestamp(info.incident_end_time),
            exit_point=str(eval_sec.asset_context.production_system)
        )

        data_consequence = (
            f"The evaluation of the associated data context indicates '{eval_sec.data_context.data_classification}' classification, "
            f"with potential cryptographic access exposure related to '{str(eval_sec.data_context.cryptographic_asset)}'."
        )

        attack_progression = [
            narrative_summary,
            progression_para,
            data_consequence
        ]

        # 3. Affected Entities
        entities = [
            f"Primary implicated account: {info.primary_entity}",
            f"Impacted production system: {str(eval_sec.asset_context.production_system)} (Asset Type: {eval_sec.asset_context.asset_type})",
            f"Customer segment: {eval_sec.customer_context.customer_segment} (Risk Profile: {eval_sec.customer_context.customer_risk_profile})"
        ]

        # 4. Business Consequences
        consequences = [
            f"Business Process: {eval_sec.business_context.business_process} (Criticality Level: {eval_sec.business_context.business_criticality})",
            f"Service Impact: {eval_sec.business_context.service_impact}",
            f"Operational Impact: {classification.operational_impact}",
            f"Financial Impact: {classification.financial_impact} (Financial Exposure: {eval_sec.transaction_context.financial_exposure})"
        ]

        return IncidentNarrative(
            narrative_summary=narrative_summary,
            attack_progression=self.formatter.format_list_to_bullets(attack_progression),
            affected_entities=self.formatter.format_list_to_bullets(entities),
            business_consequences=self.formatter.format_list_to_bullets(consequences)
        )
