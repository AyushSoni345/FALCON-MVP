from app.generators.base import BaseGenerator
from app.models.requests import UnifiedRiskAssessment
from app.models.responses import AnalystDecisionSupport

class AnalystDecisionSupportGenerator(BaseGenerator):
    """Generates the Analyst Decision Support section of the report."""

    def generate(self, assessment: UnifiedRiskAssessment) -> AnalystDecisionSupport:
        eval_sec = assessment.context_evaluation
        conf_sec = assessment.confidence_assessment
        prioritization = assessment.prioritization_decision
        response_sec = assessment.response_priority

        confidence_summary = (
            f"The overall confidence of {conf_sec.overall_confidence:.2f} is supported by strong evidence strength ({conf_sec.evidence_strength:.2f}) "
            f"and a low false positive probability ({conf_sec.false_positive_probability:.2f})."
        )

        if prioritization.escalation_required:
            escalation_rec = f"Escalation is recommended based on priority level '{prioritization.priority_level}' and analyst review requirements."
        else:
            escalation_rec = "Standard alert review. Escalation is not immediately required."

        automation_rec = self.templates.get_automation_recommendation(response_sec.automation_eligible)

        review_status = "required" if prioritization.analyst_review_required else "optional"
        analyst_notes = (
            f"Analyst review is '{review_status}'. Customer Risk Profile is '{eval_sec.customer_context.customer_risk_profile}' "
            f"and Vulnerable Customer Status is {eval_sec.customer_context.vulnerable_customer}. "
            f"High Net Worth Customer: {eval_sec.customer_context.high_net_worth_customer}."
        )

        return AnalystDecisionSupport(
            confidence_summary=confidence_summary,
            escalation_recommendation=escalation_rec,
            automation_recommendation=automation_rec,
            analyst_notes=analyst_notes
        )
