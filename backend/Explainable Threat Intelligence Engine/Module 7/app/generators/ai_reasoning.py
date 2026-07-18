from app.generators.base import BaseGenerator
from app.models.requests import UnifiedRiskAssessment
from app.models.responses import ExplainableAIReasoning

class ExplainableAIReasoningEngine(BaseGenerator):
    """Generates the Explainable AI Reasoning section of the report."""

    def generate(self, assessment: UnifiedRiskAssessment) -> ExplainableAIReasoning:
        sig = assessment.risk_signal_aggregation
        score_sec = assessment.context_aware_risk_score
        conf_sec = assessment.confidence_assessment
        ref_m5 = assessment.referenced_domain_ai_assessment

        sorted_domains = sorted(sig.contributing_domains)

        # 1. Reasoning Steps (intelligently summarized decision path)
        reasoning_steps = [
            f"Evaluated telemetry risk scores across active domains: {', '.join(sorted_domains)}.",
            f"Calibrated the base aggregated score of {sig.aggregated_score:.1f} to {score_sec.unified_risk_score:.1f} based on context metrics.",
            "Assessed final classification confidence and false positive probabilities."
        ]

        # 2. Supporting Factors (what increased confidence)
        supporting_factors = [
            f"Risk evaluation trend flagged as: '{score_sec.risk_trend}'",
            f"Evidence strength evaluated at {conf_sec.evidence_strength:.2f}",
            "Strong multi-domain correlation of behavioral and fraud signals"
        ]

        # 3. Contradictory Factors (what reduced confidence or counterbalanced)
        contradictory_factors = [
            f"False positive probability estimated at {conf_sec.false_positive_probability:.2f}",
            f"Business context confidence offset rating of {conf_sec.business_context_confidence:.2f}"
        ]

        steps_str = "; ".join(reasoning_steps)
        supporting_str = ", ".join(supporting_factors)
        contradictory_str = ", ".join(contradictory_factors)

        ai_decision_summary_text = (
            f"Multi-domain AI assessment confirmed threat activity across active domains: "
            f"{', '.join(sorted_domains)}."
        )

        explanation_summary = self.templates.get_ai_reasoning_summary(
            ai_decision_summary=ai_decision_summary_text,
            confidence=conf_sec.overall_confidence,
            steps=steps_str,
            supporting=supporting_str,
            contradictory=contradictory_str
        )

        return ExplainableAIReasoning(
            reasoning_steps=self.formatter.format_list_to_bullets(reasoning_steps),
            supporting_factors=self.formatter.format_list_to_bullets(supporting_factors),
            contradictory_factors=self.formatter.format_list_to_bullets(contradictory_factors),
            ai_decision_summary=explanation_summary
        )
