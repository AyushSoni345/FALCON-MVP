from typing import Optional
from module_8.models.input_models import ExplainableThreatReport
from module_8.models.output_models import ContinuousLearningPackage

class LearningGenerator:
    def generate_learning_package(self, verdict: str, etr: ExplainableThreatReport) -> Optional[ContinuousLearningPackage]:
        valid_verdicts = ["True Positive", "False Positive", "Benign", "Unknown"]
        if verdict not in valid_verdicts:
            raise ValueError(f"Invalid analyst verdict. Must be one of {valid_verdicts}")
            
        if verdict == "True Positive":
            label = "positive"
            priority = "High"
        elif verdict == "False Positive":
            label = "negative"
            priority = "High"
        elif verdict == "Benign":
            label = "suppression"
            priority = "Medium"
        else:
            label = "future_review"
            priority = "Low"
            
        return ContinuousLearningPackage(
            analyst_verdict=verdict,
            learning_label=label,
            contributing_patterns=etr.root_cause_analysis.contributing_factors,
            contextual_features=etr.evidence_chain.business_context,
            learning_priority=priority
        )
