from typing import List
from module_8.models.output_models import ModelOptimizationRecommendation

class OptimizationEngine:
    def generate_recommendations(self, verdict: str, notes: str) -> List[ModelOptimizationRecommendation]:
        recommendations = []
        
        if verdict == "False Positive":
            # Heuristic check on notes to determine suspected modules
            suspected = []
            if "analytics" in notes.lower() or "behavior" in notes.lower():
                suspected.append("Module 5 Behaviour Analytics")
            if "score" in notes.lower() or "weight" in notes.lower():
                suspected.append("Module 6 Risk Calibration")
            if "graph" in notes.lower() or "relation" in notes.lower():
                suspected.append("Module 3 Knowledge Graph")
                
            if not suspected:
                suspected = ["Module 5", "Module 6"] # fallback
                
            rec = ModelOptimizationRecommendation(
                suspected_affected_modules=suspected,
                optimization_target="Reduce false positive rate for this specific pattern.",
                recommendation="Review feature weights and logic contributing to this detection.",
                supporting_feedback=notes,
                retraining_candidate=True
            )
            recommendations.append(rec)
            
        return recommendations
