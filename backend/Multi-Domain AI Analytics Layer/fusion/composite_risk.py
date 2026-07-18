import logging
from typing import List
from module5.models.shared.engine_result import EngineResult, EngineStatus
from module5.models.output.assessment import CompositeRiskAssessment

logger = logging.getLogger("FALCON.Module5.Fusion.CompositeRisk")

class CompositeRiskEngine:
    """
    Combines risk and confidence scores from active AI engines into a single consolidated score.
    Does NOT calculate enterprise or business risk (business asset values are handled in Module 6).
    """
    def combine_risk_scores(self, active_results: List[EngineResult]) -> CompositeRiskAssessment:
        logger.info(f"Fusing signals for {len(active_results)} active engines.")
        if not active_results:
            return CompositeRiskAssessment(
                overall_risk_score=0.0,
                overall_risk_level="Low",
                contributing_domains=[],
                assessment_confidence=0.0,
                priority="Low"
            )

        # 1. Base score is the maximum risk score reported by any active engine
        max_risk = max(r.risk_score for r in active_results)
        
        # 2. Add concurrence multiplier
        concurrence_bonus = (len(active_results) - 1) * 5.0
        composite_risk = min(max_risk + concurrence_bonus, 100.0)

        # 3. Confidence is calculated as the average confidence of all active engines
        avg_confidence = sum(r.confidence for r in active_results) / len(active_results)

        # Map risk level
        if composite_risk <= 20.0:
            level = "Low"
        elif composite_risk <= 50.0:
            level = "Medium"
        elif composite_risk <= 80.0:
            level = "High"
        else:
            level = "Critical"

        contributing = [r.engine_name for r in active_results]

        logger.info(f"Composite risk assessment fused. Risk: {composite_risk}, Level: {level}, Confidence: {avg_confidence}")
        return CompositeRiskAssessment(
            overall_risk_score=round(composite_risk, 2),
            overall_risk_level=level,
            contributing_domains=contributing,
            assessment_confidence=round(avg_confidence, 2),
            priority=level
        )
