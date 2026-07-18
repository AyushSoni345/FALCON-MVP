import logging
from typing import List
from module5.engines.base import BaseAnalyticsEngine
from module5.models.input.incident import CorrelatedSecurityIncident
from module5.models.shared.engine_result import EngineResult, EngineStatus
from module5.engines.fraud.components import (
    FraudContextExtractor,
    TransactionAnalyzer,
    BeneficiaryAnalyzer,
    MuleAccountDetector,
    FraudPatternDetector,
    FraudRiskCalculator,
    FraudSignalGenerator,
    FraudRecommendationGenerator,
    FraudAssessmentBuilder
)
from module5.intelligence.manager import classify_signal, SignalCategory
from module5.config.settings import settings

logger = logging.getLogger("FALCON.Module5.Fraud.Engine")

class FraudAnalyticsEngine(BaseAnalyticsEngine):
    """
    Evaluates whether the incident contains financial fraud indicators.
    """
    def __init__(self):
        self.extractor = FraudContextExtractor()
        self.transaction_analyzer = TransactionAnalyzer()
        self.beneficiary_analyzer = BeneficiaryAnalyzer()
        self.mule_detector = MuleAccountDetector()
        self.pattern_detector = FraudPatternDetector()
        self.risk_calculator = FraudRiskCalculator()
        self.signal_generator = FraudSignalGenerator()
        self.recommendation_generator = FraudRecommendationGenerator()
        self.builder = FraudAssessmentBuilder()

    @property
    def engine_name(self) -> str:
        return "Fraud"

    async def analyze(
        self, 
        incident: CorrelatedSecurityIncident, 
        external_signals: List[str]
    ) -> EngineResult:
        logger.info("Fraud Engine started analysis.")
        try:
            # 1. Extract context
            context = self.extractor.extract(incident)
            logger.debug("Financial context extraction completed.")

            # 2. Analyze transactions
            transactions = self.transaction_analyzer.analyze_transactions(context, incident)

            # 3. Analyze beneficiaries
            beneficiaries = self.beneficiary_analyzer.analyze_beneficiaries(context, incident)

            # 4. Detect mule indicators
            mule = self.mule_detector.detect_mule(context, incident)

            # 5. Group into higher-level fraud patterns
            patterns = self.pattern_detector.detect_patterns(transactions, beneficiaries, mule, incident)

            # 6. Calculate fraud risk and confidence
            risk_score, confidence = self.risk_calculator.calculate(
                transactions, 
                beneficiaries, 
                mule, 
                incident.confidence_assessment.overall_confidence
            )

            # Amplification from external signals (e.g. Behavioural Anomalies or Cyber Threat signals)
            has_supporting_signal = False
            for sig in external_signals:
                cat = classify_signal(sig)
                if cat in [
                    SignalCategory.CREDENTIAL_MISUSE,
                    SignalCategory.SESSION_ABUSE,
                    SignalCategory.BEHAVIOURAL_DRIFT,
                    SignalCategory.CREDENTIAL_COMPROMISE,
                    SignalCategory.MALWARE_INFECTION,
                    SignalCategory.LATERAL_MOVEMENT,
                    SignalCategory.PRIVILEGE_ESCALATION
                ]:
                    has_supporting_signal = True

            if has_supporting_signal and risk_score > 0:
                logger.info("External behavioral/cyber signals reinforce fraud likelihood. Amplifying fraud confidence and risk.")
                risk_score = min(risk_score + 10.0, 100.0)
                confidence = min(confidence + 12.0, 100.0)

            # 7. Generate shared signals
            shared_signals = self.signal_generator.generate_signals(patterns, transactions, mule)

            # 8. Generate recommendations
            recommendations = self.recommendation_generator.generate_recommendations(patterns, transactions, mule)

            # Determine engine status
            # Becomes ACTIVE if risk score exceeds configured threshold and active findings exist
            is_active = (risk_score >= settings.FRAUD_RISK_THRESHOLD) and (len(transactions) > 0 or len(beneficiaries) > 0 or mule is not None)
            status = EngineStatus.ACTIVE if is_active else EngineStatus.NO_SIGNIFICANT_FINDINGS

            # Gather supporting evidence references
            evidence = []
            if context["affected_transactions"]:
                evidence.extend(context["affected_transactions"])
            if context["affected_accounts"]:
                evidence.extend(context["affected_accounts"])
            # Match UUIDs of related events from timeline steps
            evidence.extend([step.event_uuid for step in incident.incident_timeline if "TRANSFER" in step.action.upper() or "BENEFICIARY" in step.action.upper()])
            evidence = list(set(evidence))

            if status == EngineStatus.ACTIVE:
                # Build detailed sub-assessment
                assessment = self.builder.build(
                    patterns=patterns,
                    transactions=transactions,
                    beneficiaries=beneficiaries,
                    mule=mule,
                    risk_score=risk_score,
                    confidence=confidence,
                    evidence=evidence
                )
                assessment_dict = assessment.model_dump()
            else:
                assessment_dict = None

            findings = [f"Anomalous transaction activity of {tx.amount} {tx.currency}: {tx.risk_reason}" for tx in transactions]
            if mule:
                findings.extend(mule.supporting_evidence)

            logger.info(f"Fraud Engine analysis completed. Status: {status.value}, Risk: {risk_score}")
            return EngineResult(
                engine_name=self.engine_name,
                status=status,
                confidence=confidence,
                risk_score=risk_score,
                findings=findings,
                supporting_evidence=evidence,
                shared_signals=shared_signals,
                recommendations=recommendations,
                fraud_assessment=assessment_dict
            )

        except Exception as e:
            logger.error(f"Fraud Engine failed during analysis: {str(e)}", exc_info=True)
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
