import logging
import asyncio
from typing import Dict, List
from module5.models.input.incident import CorrelatedSecurityIncident
from module5.models.output.assessment import DomainAIAssessment
from module5.models.shared.engine_result import EngineResult, EngineStatus
from module5.utils.validation import validate_incident
from module5.engines.behaviour.engine import BehaviourAnalyticsEngine
from module5.engines.fraud.engine import FraudAnalyticsEngine
from module5.engines.cyber.engine import CyberThreatAnalyticsEngine
from module5.engines.quantum.engine import QuantumRiskAnalyticsEngine
from module5.intelligence.manager import CrossDomainIntelligenceManager
from module5.fusion.composite_risk import CompositeRiskEngine
from module5.explanation.explanation_engine import AIExplanationEngine
from module5.builder.assessment_builder import DomainAssessmentBuilder
from module5.exceptions.exceptions import AnalyticsPipelineException

logger = logging.getLogger("FALCON.Module5.Orchestrator")

class Module5Orchestrator:
    """
    Coordinates the complete lifecycle of Module 5 analysis.
    Controls validation, category identification, two-pass execution of engines,
    cross-domain intelligence sharing, risk fusion, and final output building.
    """
    def __init__(self):
        self.engines = [
            BehaviourAnalyticsEngine(),
            FraudAnalyticsEngine(),
            CyberThreatAnalyticsEngine(),
            QuantumRiskAnalyticsEngine()
        ]
        self.intel_manager = CrossDomainIntelligenceManager()
        self.risk_engine = CompositeRiskEngine()
        self.explanation_engine = AIExplanationEngine()
        self.builder = DomainAssessmentBuilder()

    def identify_category(self, incident: CorrelatedSecurityIncident) -> str:
        """
        Determines the category of the incident (Cyber, Financial, Hybrid, Quantum, Unknown).
        Guarded by incoming metadata and timeline heuristics.
        """
        # 1. Use original category if available and valid
        orig_cat = incident.incident_information.incident_category
        valid_categories = {"Cyber", "Financial", "Hybrid", "Quantum", "Unknown"}
        if orig_cat in valid_categories:
            return orig_cat

        # 2. Heuristics fallback
        summary = (incident.ai_reasoning.anomaly_summary or "").lower()
        inc_type = (incident.incident_information.incident_type or "").lower()
        
        has_cyber = any(w in summary or w in inc_type for w in ["malware", "compromise", "credential", "lateral", "brute-force", "vpn"])
        has_financial = any(w in summary or w in inc_type for w in ["transfer", "payment", "beneficiary", "mule", "transaction"])
        has_quantum = any(w in summary or w in inc_type for w in ["quantum", "hndl", "decrypt", "exfiltration", "encrypted", "pki"])

        if has_quantum:
            return "Quantum"
        if has_cyber and has_financial:
            return "Hybrid"
        if has_cyber:
            return "Cyber"
        if has_financial:
            return "Financial"
        
        return "Unknown"

    async def analyze(self, incident: CorrelatedSecurityIncident) -> DomainAIAssessment:
        logger.info("Module 5 assessment started.")

        # 1. Validate incoming incident
        validate_incident(incident)
        logger.info("Validation completed.")

        # 2. Identify category
        category = self.identify_category(incident)
        logger.info(f"Identified incident category: {category}")

        # 3. First Pass - Execute all engines concurrently
        logger.info("Engine execution started - Pass 1.")
        tasks_pass1 = [
            engine.analyze(incident, []) 
            for engine in self.engines
        ]
        results_pass1: List[EngineResult] = await asyncio.gather(*tasks_pass1, return_exceptions=True)
        
        # Handle exceptions in gathered tasks
        cleaned_results_pass1: List[EngineResult] = []
        for i, res in enumerate(results_pass1):
            engine_name = self.engines[i].engine_name
            if isinstance(res, Exception):
                logger.error(f"Engine {engine_name} crashed in Pass 1: {str(res)}")
                cleaned_results_pass1.append(EngineResult(
                    engine_name=engine_name,
                    status=EngineStatus.ERROR,
                    confidence=0.0,
                    risk_score=0.0,
                    engine_metadata={"error": str(res)}
                ))
            else:
                cleaned_results_pass1.append(res)
        logger.info("Engine execution completed - Pass 1.")

        # 4. Intelligence Sharing - Coordinate cross-domain intelligence
        routed_signals = self.intel_manager.route_signals(cleaned_results_pass1)
        logger.info("Intelligence sharing completed.")

        # 5. Second Pass - Execute all engines with external signals
        logger.info("Engine execution started - Pass 2.")
        tasks_pass2 = [
            engine.analyze(incident, routed_signals.get(engine.engine_name, []))
            for engine in self.engines
        ]
        results_pass2: List[EngineResult] = await asyncio.gather(*tasks_pass2, return_exceptions=True)

        cleaned_results_pass2: List[EngineResult] = []
        for i, res in enumerate(results_pass2):
            engine_name = self.engines[i].engine_name
            if isinstance(res, Exception):
                logger.error(f"Engine {engine_name} crashed in Pass 2: {str(res)}")
                cleaned_results_pass2.append(EngineResult(
                    engine_name=engine_name,
                    status=EngineStatus.ERROR,
                    confidence=0.0,
                    risk_score=0.0,
                    engine_metadata={"error": str(res)}
                ))
            else:
                cleaned_results_pass2.append(res)
        logger.info("Engine execution completed - Pass 2.")

        # Filter active engines
        active_results = [r for r in cleaned_results_pass2 if r.status == EngineStatus.ACTIVE]

        # 6. Signal Fusion
        composite_risk = self.risk_engine.combine_risk_scores(active_results)

        # 7. Generate explanation
        explanation = self.explanation_engine.generate_explanation(active_results)

        # 8. Build assessment
        assessment = self.builder.build_assessment(
            incident=incident,
            category=category,
            engine_results=cleaned_results_pass2,
            routed_signals=routed_signals,
            composite_risk=composite_risk,
            explanation=explanation
        )
        logger.info("Assessment built.")

        logger.info("Module 5 assessment returned.")
        return assessment
