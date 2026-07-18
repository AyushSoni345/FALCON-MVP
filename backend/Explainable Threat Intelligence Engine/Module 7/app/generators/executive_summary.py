from app.generators.base import BaseGenerator
from app.models.requests import UnifiedRiskAssessment
from app.models.responses import ExecutiveSummary

class ExecutiveSummaryGenerator(BaseGenerator):
    """Generates the Executive Summary section of the report."""

    def generate(self, assessment: UnifiedRiskAssessment) -> ExecutiveSummary:
        info = assessment.assessment_information
        eval_sec = assessment.context_evaluation
        score_sec = assessment.context_aware_risk_score
        prioritization = assessment.prioritization_decision
        classification = assessment.incident_classification

        # Resolve active domains list
        active_domains = []
        ref_m5 = assessment.referenced_domain_ai_assessment
        if isinstance(ref_m5.active_domain_assessments, list):
            active_domains = ref_m5.active_domain_assessments
        else:
            act = ref_m5.active_domain_assessments
            if act:
                if getattr(act, "behaviour_assessment", None): active_domains.append("Behaviour")
                if getattr(act, "fraud_assessment", None): active_domains.append("Fraud")
                if getattr(act, "cyber_assessment", None): active_domains.append("Cyber")
                if getattr(act, "quantum_assessment", None): active_domains.append("Quantum")

        # Determine primary cause dynamically based on active domains
        if "Behaviour" in active_domains or "Fraud" in active_domains:
            primary_cause_desc = f"Credential Exposure ({eval_sec.data_context.credential_exposure})"
        elif "Cyber" in active_domains:
            primary_cause_desc = f"Infrastructure Vulnerability ({str(eval_sec.asset_context.production_system)})"
        elif "Quantum" in active_domains:
            primary_cause_desc = f"Harvest-Now-Decrypt-Later Threat ({str(eval_sec.data_context.cryptographic_asset)})"
        else:
            primary_cause_desc = "Multi-domain security event baseline threshold anomaly"

        # risk_level is string
        risk_lvl_str = score_sec.risk_level
        if hasattr(risk_lvl_str, "value"):
            risk_lvl_str = risk_lvl_str.value

        incident_overview = self.templates.get_executive_summary_overview(
            risk_level=str(risk_lvl_str),
            classification=classification.final_incident_type,
            primary_entity=info.primary_entity,
            primary_cause=primary_cause_desc,
            risk_score=score_sec.unified_risk_score,
            business_process=eval_sec.business_context.business_process,
            business_impact=classification.business_impact,
            recommended_priority=prioritization.priority_level
        )

        return ExecutiveSummary(
            incident_overview=incident_overview,
            unified_risk_score=score_sec.unified_risk_score,
            risk_level=risk_lvl_str,
            primary_cause=primary_cause_desc,
            business_impact=classification.business_impact,
            recommended_priority=prioritization.priority_level
        )
