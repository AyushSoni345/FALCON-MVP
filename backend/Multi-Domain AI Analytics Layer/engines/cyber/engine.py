import logging
from typing import List
from module5.engines.base import BaseAnalyticsEngine
from module5.models.input.incident import CorrelatedSecurityIncident
from module5.models.shared.engine_result import EngineResult, EngineStatus
from module5.engines.cyber.components import (
    CyberContextExtractor,
    AttackIndicatorDetector,
    AttackPatternDetector,
    AttackStageClassifier,
    CompromisedAssetAnalyzer,
    LateralMovementAnalyzer,
    MalwareAnalyzer,
    CyberRiskCalculator,
    CyberSignalGenerator,
    CyberRecommendationGenerator,
    CyberAssessmentBuilder
)
from module5.intelligence.manager import classify_signal, SignalCategory
from module5.config.settings import settings

logger = logging.getLogger("FALCON.Module5.Cyber.Engine")

class CyberThreatAnalyticsEngine(BaseAnalyticsEngine):
    """
    Evaluates whether the incident contains evidence of cyber attacks targeting banking infrastructure.
    """
    def __init__(self):
        self.extractor = CyberContextExtractor()
        self.indicator_detector = AttackIndicatorDetector()
        self.pattern_detector = AttackPatternDetector()
        self.stage_classifier = AttackStageClassifier()
        self.asset_analyzer = CompromisedAssetAnalyzer()
        self.lateral_analyzer = LateralMovementAnalyzer()
        self.malware_analyzer = MalwareAnalyzer()
        self.risk_calculator = CyberRiskCalculator()
        self.signal_generator = CyberSignalGenerator()
        self.recommendation_generator = CyberRecommendationGenerator()
        self.builder = CyberAssessmentBuilder()

    @property
    def engine_name(self) -> str:
        return "Cyber"

    async def analyze(
        self, 
        incident: CorrelatedSecurityIncident, 
        external_signals: List[str]
    ) -> EngineResult:
        logger.info("Cyber Threat Engine started analysis.")
        try:
            # 1. Extract context
            context = self.extractor.extract(incident)
            logger.debug("Infrastructure context extraction completed.")

            # 2. Detect indicators
            indicators = self.indicator_detector.detect_indicators(context, incident)

            # 3. Identify primary attack pattern
            pattern = self.pattern_detector.detect_patterns(indicators, incident)

            # 4. Determine attack stage
            stage = self.stage_classifier.classify_stage(pattern, incident)

            # 5. Analyze compromised assets
            compromised = self.asset_analyzer.analyze_assets(context, incident)

            # 6. Analyze lateral movements
            lateral = self.lateral_analyzer.analyze_movement(context, incident)

            # 7. Analyze malware
            malware = self.malware_analyzer.analyze_malware(context, incident)

            # 8. Calculate cyber risk and confidence
            risk_score, confidence = self.risk_calculator.calculate(
                compromised, 
                lateral, 
                malware, 
                incident.confidence_assessment.overall_confidence
            )

            # Amplification from external signals (e.g. Behavioural Anomalies or Quantum Risks)
            has_supporting_signal = False
            for sig in external_signals:
                cat = classify_signal(sig)
                if cat in [
                    SignalCategory.CREDENTIAL_MISUSE,
                    SignalCategory.SESSION_ABUSE,
                    SignalCategory.ACCOUNT_TAKEOVER,
                    SignalCategory.BENEFICIARY_ABUSE,
                    SignalCategory.RAPID_TRANSFER,
                    SignalCategory.BULK_ENCRYPTED_TRANSFER,
                    SignalCategory.CRYPTOGRAPHIC_ENUMERATION,
                    SignalCategory.HNDL_DETECTION,
                    SignalCategory.LONG_LIVED_SESSION
                ]:
                    has_supporting_signal = True

            if has_supporting_signal and risk_score > 0:
                logger.info("External behavioural/quantum signals reinforce cyber assessment. Amplifying confidence.")
                risk_score = min(risk_score + 5.0, 100.0)
                confidence = min(confidence + 10.0, 100.0)

            # 9. Generate shared signals
            shared_signals = self.signal_generator.generate_signals(pattern, stage, lateral, malware)

            # 10. Generate recommendations
            recommendations = self.recommendation_generator.generate_recommendations(compromised, lateral, malware)

            # Determine engine status
            # Becomes ACTIVE if risk score exceeds configured threshold and there are actual cyber exploit indicators
            is_active = (risk_score >= settings.CYBER_RISK_THRESHOLD) and (
                len(indicators) > 0 or 
                malware is not None or 
                lateral is not None or
                (pattern != "Unknown Exploitation Chain" and len(compromised) > 0)
            )
            status = EngineStatus.ACTIVE if is_active else EngineStatus.NO_SIGNIFICANT_FINDINGS

            # Gather supporting evidence references
            evidence = []
            if context["compromised_node_ids"]:
                evidence.extend(context["compromised_node_ids"])
            evidence.extend(context["malware_evidence"])
            evidence.extend(context["ioc_matches"])
            evidence = list(set(evidence))

            if status == EngineStatus.ACTIVE:
                # Build detailed sub-assessment
                assessment = self.builder.build(
                    pattern=pattern,
                    stage=stage,
                    compromised=compromised,
                    lateral=lateral,
                    malware=malware,
                    risk_score=risk_score,
                    confidence=confidence,
                    evidence=evidence
                )
                assessment_dict = assessment.model_dump()
            else:
                assessment_dict = None

            findings = indicators if indicators else [f"Cyber threat activity identified in stage: {stage}"]

            logger.info(f"Cyber Threat Engine completed. Status: {status.value}, Risk: {risk_score}")
            return EngineResult(
                engine_name=self.engine_name,
                status=status,
                confidence=confidence,
                risk_score=risk_score,
                findings=findings,
                supporting_evidence=evidence,
                shared_signals=shared_signals,
                recommendations=recommendations,
                cyber_assessment=assessment_dict
            )

        except Exception as e:
            logger.error(f"Cyber Threat Engine failed during analysis: {str(e)}", exc_info=True)
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
