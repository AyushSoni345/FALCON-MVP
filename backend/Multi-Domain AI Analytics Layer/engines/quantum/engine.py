import logging
from typing import List
from module5.engines.base import BaseAnalyticsEngine
from module5.models.input.incident import CorrelatedSecurityIncident
from module5.models.shared.engine_result import EngineResult, EngineStatus
from module5.engines.quantum.components import (
    QuantumContextExtractor,
    EncryptedDataAnalyzer,
    HNDLIndicatorDetector,
    LegacyCryptoAnalyzer,
    QuantumRiskCalculator,
    QuantumSignalGenerator,
    QuantumRecommendationGenerator,
    QuantumAssessmentBuilder
)
from module5.intelligence.manager import classify_signal, SignalCategory
from module5.config.settings import settings

logger = logging.getLogger("FALCON.Module5.Quantum.Engine")

class QuantumRiskAnalyticsEngine(BaseAnalyticsEngine):
    """
    Evaluates whether the incident contains indicators of future quantum-related risks (e.g. HNDL).
    """
    def __init__(self):
        self.extractor = QuantumContextExtractor()
        self.exposure_analyzer = EncryptedDataAnalyzer()
        self.indicator_detector = HNDLIndicatorDetector()
        self.legacy_analyzer = LegacyCryptoAnalyzer()
        self.risk_calculator = QuantumRiskCalculator()
        self.signal_generator = QuantumSignalGenerator()
        self.recommendation_generator = QuantumRecommendationGenerator()
        self.builder = QuantumAssessmentBuilder()

    @property
    def engine_name(self) -> str:
        return "Quantum"

    async def analyze(
        self, 
        incident: CorrelatedSecurityIncident, 
        external_signals: List[str]
    ) -> EngineResult:
        logger.info("Quantum Risk Engine started analysis.")
        try:
            # 1. Extract context
            context = self.extractor.extract(incident)
            logger.debug("Cryptographic context extraction completed.")

            # 2. Analyze encrypted data exposure
            exposures = self.exposure_analyzer.analyze_exposure(context, incident)

            # 3. Detect HNDL indicators
            indicators = self.indicator_detector.detect_indicators(context, incident)

            # 4. Analyze legacy cryptography
            legacy = self.legacy_analyzer.analyze_legacy_crypto(context, incident)

            # 5. Calculate quantum risk and confidence
            risk_score, confidence = self.risk_calculator.calculate(
                indicators, 
                exposures, 
                legacy, 
                incident.confidence_assessment.overall_confidence
            )

            # Amplification from external signals (e.g. C2/Exfiltration detected by Cyber Engine)
            has_exfiltration_risk = False
            for sig in external_signals:
                cat = classify_signal(sig)
                if cat in [
                    SignalCategory.LATERAL_MOVEMENT,
                    SignalCategory.MALWARE_INFECTION,
                    SignalCategory.PRIVILEGE_ESCALATION,
                    SignalCategory.BULK_ENCRYPTED_TRANSFER
                ]:
                    has_exfiltration_risk = True

            if has_exfiltration_risk and risk_score > 0:
                logger.info("External cyber exfiltration signals reinforce HNDL collection. Amplifying Quantum risk sub-score.")
                risk_score = min(risk_score + 15.0, 100.0)
                confidence = min(confidence + 8.0, 100.0)

            # 6. Generate shared signals
            shared_signals = self.signal_generator.generate_signals(indicators, exposures)

            # 7. Generate recommendations
            recommendations = self.recommendation_generator.generate_recommendations(indicators, legacy)

            # Determine engine status
            # Becomes ACTIVE if risk score exceeds configured threshold and active findings exist
            is_active = (risk_score >= settings.QUANTUM_RISK_THRESHOLD) and (len(indicators) > 0 or len(exposures) > 0 or len(legacy) > 0)
            status = EngineStatus.ACTIVE if is_active else EngineStatus.NO_SIGNIFICANT_FINDINGS

            # Gather supporting evidence references
            evidence = []
            evidence.extend([ex["uuid"] for ex in context["exfiltrations"]])
            evidence.extend([ka["uuid"] for ka in context["key_accesses"]])
            evidence.extend([la["node_id"] for la in context["legacy_algorithms"]])
            evidence = list(set(evidence))

            if status == EngineStatus.ACTIVE:
                # Build detailed sub-assessment
                assessment = self.builder.build(
                    indicators=indicators,
                    exposures=exposures,
                    legacy=legacy,
                    risk_score=risk_score,
                    confidence=confidence,
                    evidence=evidence
                )
                assessment_dict = assessment.model_dump()
            else:
                assessment_dict = None

            findings = [ind.description for ind in indicators]
            findings.extend([f"Vulnerable legacy asset exposed: {l.asset_name} using {l.algorithm}" for l in legacy])

            logger.info(f"Quantum Risk Engine completed. Status: {status.value}, Risk: {risk_score}")
            return EngineResult(
                engine_name=self.engine_name,
                status=status,
                confidence=confidence,
                risk_score=risk_score,
                findings=findings,
                supporting_evidence=evidence,
                shared_signals=shared_signals,
                recommendations=recommendations,
                quantum_assessment=assessment_dict
            )

        except Exception as e:
            logger.error(f"Quantum Risk Engine failed during analysis: {str(e)}", exc_info=True)
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
