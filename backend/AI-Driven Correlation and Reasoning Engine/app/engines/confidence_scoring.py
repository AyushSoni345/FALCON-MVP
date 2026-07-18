from typing import Any, Dict, List
from module4.app.models.models import SecurityGraphEvent, ThreatHypothesis
from module4.app.engines.interfaces import BaseConfidenceScoringEngine

class ConfidenceScoringEngine(BaseConfidenceScoringEngine):
    """
    Computes multi-dimensional confidence metrics assessing
    the quality, consistency, and completeness of incident reasoning.
    """

    def calculate_confidence(
        self,
        events: List[SecurityGraphEvent],
        evidence_output: Dict[str, Any],
        hypotheses: List[ThreatHypothesis]
    ) -> Dict[str, Any]:
        evidence_score = evidence_output.get("evidence_score", 0.5)
        contradictory = evidence_output.get("contradictory_evidence", [])
        IOC_matches = evidence_output.get("IOC_matches", [])
        malware_matches = evidence_output.get("malware_matches", [])
        fraud_matches = evidence_output.get("fraud_matches", [])
        behavioral_anomalies = evidence_output.get("behavioral_anomalies", [])

        # Temporal confidence based on event chronology and timing gaps
        temporal_confidence = 0.8
        if len(events) > 1:
            # Check timestamps spacing
            timestamps = sorted([e.event_context.normalized_timestamp for e in events])
            span = (timestamps[-1] - timestamps[0]).total_seconds()
            if span < 60.0:  # highly rapid sequence raises confidence of automated/correlated attack
                temporal_confidence = 0.95
            elif span > 86400.0:  # very long span reduces correlation confidence
                temporal_confidence = 0.65

        # Graph confidence based on degree of connection (shared entities)
        # We can extract this or compute it here
        # If we have shared entities, graph confidence is higher
        graph_confidence = 0.7 if len(evidence_output.get("graph_paths", [])) > 0 else 0.5

        # Behavioral confidence based on anomalies
        behavioral_confidence = round(min(1.0, 0.4 + 0.15 * len(behavioral_anomalies)), 2)

        # Threat Intelligence confidence based on IOCs and Malware tags
        threat_intelligence_confidence = round(min(1.0, 0.4 + 0.2 * (len(IOC_matches) + len(malware_matches))), 2)

        # Fraud confidence based on transaction/beneficiary context
        fraud_confidence = round(min(1.0, 0.4 + 0.2 * len(fraud_matches)), 2)

        # Uncertainty score increases with contradictions or sparse events
        uncertainty_score = 0.2
        if contradictory:
            uncertainty_score += min(0.5, 0.15 * len(contradictory))
        if len(events) <= 1:
            uncertainty_score += 0.2

        # Overall confidence is a weighted average of dimensions adjusted by uncertainty
        max_hypothesis_likelihood = hypotheses[0].likelihood if hypotheses else 0.5
        overall_confidence = round(
            max(
                0.1,
                min(
                    0.99,
                    (
                        temporal_confidence * 0.15 +
                        graph_confidence * 0.2 +
                        behavioral_confidence * 0.2 +
                        threat_intelligence_confidence * 0.25 +
                        fraud_confidence * 0.2
                    ) * 0.8 +
                    max_hypothesis_likelihood * 0.2 -
                    uncertainty_score * 0.1
                )
            ),
            2
        )

        return {
            "overall_confidence": overall_confidence,
            "temporal_confidence": temporal_confidence,
            "graph_confidence": graph_confidence,
            "behavioral_confidence": behavioral_confidence,
            "threat_intelligence_confidence": threat_intelligence_confidence,
            "fraud_confidence": fraud_confidence,
            "evidence_score": evidence_score,
            "uncertainty_score": round(uncertainty_score, 2)
        }
