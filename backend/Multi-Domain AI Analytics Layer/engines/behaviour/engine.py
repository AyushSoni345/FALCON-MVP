import logging
from typing import List
from module5.engines.base import BaseAnalyticsEngine
from module5.models.input.incident import CorrelatedSecurityIncident
from module5.models.shared.engine_result import EngineResult, EngineStatus
from module5.engines.behaviour.components import (
    BehaviourContextExtractor,
    BehaviourProfileProvider,
    BehaviourComparator,
    BehaviourAnomalyDetector,
    BehaviourPatternDetector,
    BehaviourRiskCalculator,
    BehaviourSignalGenerator,
    BehaviourRecommendationGenerator,
    BehaviourAssessmentBuilder
)
from module5.intelligence.manager import classify_signal, SignalCategory
from module5.config.settings import settings

logger = logging.getLogger("FALCON.Module5.Behaviour.Engine")

class BehaviourAnalyticsEngine(BaseAnalyticsEngine):
    """
    Evaluates whether the incident contains behavioural anomalies indicating suspicious human or device activity.
    """
    def __init__(self):
        self.extractor = BehaviourContextExtractor()
        self.profile_provider = BehaviourProfileProvider()
        self.comparator = BehaviourComparator()
        self.anomaly_detector = BehaviourAnomalyDetector()
        self.pattern_detector = BehaviourPatternDetector()
        self.risk_calculator = BehaviourRiskCalculator()
        self.signal_generator = BehaviourSignalGenerator()
        self.recommendation_generator = BehaviourRecommendationGenerator()
        self.builder = BehaviourAssessmentBuilder()

    @property
    def engine_name(self) -> str:
        return "Behaviour"

    async def analyze(
        self, 
        incident: CorrelatedSecurityIncident, 
        external_signals: List[str]
    ) -> EngineResult:
        logger.info("Behaviour Engine started analysis.")
        try:
            # 1. Extract context
            context = self.extractor.extract(incident)
            logger.debug("Context extraction completed.")

            # 2. Load behaviour profile
            profile = self.profile_provider.get_profile(incident, context)

            # 3. Compare current behaviour against baseline
            deviations = self.comparator.compare(context, profile)
            logger.debug("Baseline comparison completed.")

            # 4. Detect anomalies
            anomalies = self.anomaly_detector.detect(incident, context, deviations)
            logger.debug(f"Detected {len(anomalies)} behavioral anomalies.")

            # 5. Detect patterns
            patterns = self.pattern_detector.detect_patterns(anomalies)
            logger.debug("Behavioural patterns generated.")

            # Adjustments based on incoming signals (Cross-Domain signal amplification)
            has_compromise_signal = False
            for sig in external_signals:
                cat = classify_signal(sig)
                if cat in [
                    SignalCategory.CREDENTIAL_COMPROMISE,
                    SignalCategory.MALWARE_INFECTION,
                    SignalCategory.LATERAL_MOVEMENT,
                    SignalCategory.PRIVILEGE_ESCALATION,
                    SignalCategory.ACCOUNT_TAKEOVER
                ]:
                    has_compromise_signal = True

            # 6. Calculate risk and confidence
            risk_score, confidence = self.risk_calculator.calculate(
                anomalies, 
                patterns, 
                incident.confidence_assessment.overall_confidence
            )

            # If external signals reinforce anomaly, boost confidence and risk
            if has_compromise_signal and risk_score > 0:
                logger.info("External signals reinforce behaviour. Amplifying score.")
                risk_score = min(risk_score + 10.0, 100.0)
                confidence = min(confidence + 5.0, 100.0)

            # 7. Generate shared signals
            shared_signals = self.signal_generator.generate_signals(anomalies, patterns)

            # 8. Generate recommendations
            recommendations = self.recommendation_generator.generate_recommendations(anomalies, patterns)

            # Determine engine status
            # It becomes ACTIVE if risk_score exceeds configured threshold and there are anomalies
            is_active = (risk_score >= settings.BEHAVIOUR_RISK_THRESHOLD) and (len(anomalies) > 0)
            status = EngineStatus.ACTIVE if is_active else EngineStatus.NO_SIGNIFICANT_FINDINGS

            # Supporting evidence references
            evidence = list({step.event_uuid for step in incident.incident_timeline if step.action.upper() in ["LOGIN", "AUTHENTICATE"]})
            evidence.extend(incident.incident_context.affected_devices)
            evidence = list(set(evidence))

            if status == EngineStatus.ACTIVE:
                # Build detailed sub-assessment
                assessment = self.builder.build(
                    anomalies=anomalies,
                    patterns=patterns,
                    risk_score=risk_score,
                    confidence=confidence,
                    evidence=evidence
                )
                assessment_dict = assessment.model_dump()
            else:
                assessment_dict = None

            findings = [anom.description for anom in anomalies]

            logger.info(f"Behaviour Engine analysis completed. Status: {status.value}, Risk: {risk_score}")
            return EngineResult(
                engine_name=self.engine_name,
                status=status,
                confidence=confidence,
                risk_score=risk_score,
                findings=findings,
                supporting_evidence=evidence,
                shared_signals=shared_signals,
                recommendations=recommendations,
                behaviour_assessment=assessment_dict
            )

        except Exception as e:
            logger.error(f"Behaviour Engine failed during analysis: {str(e)}", exc_info=True)
            return EngineResult(
                engine_name=self.engine_name,
                status=EngineStatus.ERROR,
                confidence=0.0,
                risk_score=0.0,
                findings=[],
                supporting_evidence=[],
                shared_signals=[],
                recommendations=[],
                engine_metadata={"error": str(e)}
            )
