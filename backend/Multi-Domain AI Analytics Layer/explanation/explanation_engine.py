import logging
from typing import List
from module5.models.shared.engine_result import EngineResult
from module5.models.output.assessment import AIExplanation

logger = logging.getLogger("FALCON.Module5.Explanation.Engine")

class AIExplanationEngine:
    """
    Summarizes which engines contributed to the Module 5 Domain Assessment and why.
    Does NOT write full analyst narrative reports (which belongs to Module 7).
    """
    def generate_explanation(self, active_results: List[EngineResult]) -> AIExplanation:
        logger.info("Generating explanation for active engines.")
        if not active_results:
            return AIExplanation(
                explanation_summary="No active analytics engines identified significant threat indicators for this incident.",
                contributing_engines=[]
            )

        contributing = [r.engine_name for r in active_results]
        
        summaries = []
        for r in active_results:
            findings_str = ", ".join(r.findings[:3])
            summaries.append(f"{r.engine_name} Engine (Risk: {r.risk_score}, Conf: {r.confidence}%) identified: [{findings_str}]")

        summary_text = (
            f"Multi-Domain AI assessment compiled from active engines: {', '.join(contributing)}. "
            f"Key contributing factors: " + "; ".join(summaries) + "."
        )

        logger.debug(f"Explanation generated: {summary_text}")
        return AIExplanation(
            explanation_summary=summary_text,
            contributing_engines=contributing
        )
