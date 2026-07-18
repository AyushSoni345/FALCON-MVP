import logging
import threading
from datetime import datetime, timezone
from typing import Dict, List, Optional
from module5.models.input.incident import CorrelatedSecurityIncident
from module5.models.shared.engine_result import EngineResult, EngineStatus
from module5.models.output.assessment import (
    DomainAIAssessment,
    AssessmentInformation,
    ActiveDomainAssessments,
    ReferencedCorrelatedSecurityIncident,
    CompositeRiskAssessment,
    AIExplanation
)

logger = logging.getLogger("FALCON.Module5.Builder.AssessmentBuilder")

class DomainAssessmentBuilder:
    """
    Assembles the final DomainAIAssessment output contract model,
    populating all required references, compiling recommendations, and omitting inactive engines.
    """
    _counter = 1
    _lock = threading.Lock()

    @classmethod
    def _get_next_id(cls, timestamp: datetime) -> str:
        with cls._lock:
            seq = cls._counter
            cls._counter += 1
        return f"DAA-{timestamp.strftime('%Y%m%d')}-{seq:04d}"

    def build_assessment(
        self,
        incident: CorrelatedSecurityIncident,
        category: str,
        engine_results: List[EngineResult],
        routed_signals: Dict[str, List[str]],
        composite_risk: CompositeRiskAssessment,
        explanation: AIExplanation
    ) -> DomainAIAssessment:
        logger.info(f"Assembling final DomainAIAssessment for incident: {incident.incident_information.incident_id}")
        timestamp = datetime.now(timezone.utc)
        assessment_id = self._get_next_id(timestamp)

        # 1. Identify active engines
        active_results = [r for r in engine_results if r.status == EngineStatus.ACTIVE]
        active_domains = [r.engine_name for r in active_results]

        # 2. Populate Assessment Information
        info = AssessmentInformation(
            assessment_id=assessment_id,
            incident_id=incident.incident_information.incident_id,
            incident_category=category,
            assessment_timestamp=timestamp,
            active_domains=active_domains
        )

        # 3. Pull sub-assessments
        beh_assess = None
        frd_assess = None
        cyb_assess = None
        qtm_assess = None

        for r in active_results:
            if r.engine_name == "Behaviour" and r.behaviour_assessment:
                from module5.models.output.assessment import BehaviourAssessment
                beh_assess = BehaviourAssessment(**r.behaviour_assessment)
            elif r.engine_name == "Fraud" and r.fraud_assessment:
                from module5.models.output.assessment import FraudAssessment
                frd_assess = FraudAssessment(**r.fraud_assessment)
            elif r.engine_name == "Cyber" and r.cyber_assessment:
                from module5.models.output.assessment import CyberAssessment
                cyb_assess = CyberAssessment(**r.cyber_assessment)
            elif r.engine_name == "Quantum" and r.quantum_assessment:
                from module5.models.output.assessment import QuantumAssessment
                qtm_assess = QuantumAssessment(**r.quantum_assessment)

        active_assessments = None
        if active_results:
            active_assessments = ActiveDomainAssessments(
                behaviour_assessment=beh_assess,
                fraud_assessment=frd_assess,
                cyber_assessment=cyb_assess,
                quantum_assessment=qtm_assess
            )

        # 4. Consolidate cross-domain intelligence description list
        intel_list = []
        for target_engine, signals in routed_signals.items():
            for sig in signals:
                intel_list.append(f"Signal routed to {target_engine}: {sig}")

        # 5. Consolidate recommended actions from active engines
        recommendations = []
        for r in active_results:
            recommendations.extend(r.recommendations)
        # Deduplicate
        recommendations = list(set(recommendations))

        # 6. Populate Referenced Incident
        timeline_ref = [step.sequence_number for step in incident.incident_timeline]
        
        graph_ref = []
        for node in incident.attack_graph.attack_nodes:
            graph_ref.append(node.node_id)
        for rel in incident.attack_graph.attack_relationships:
            graph_ref.append(rel.relationship_id)
            
        hypothesis_ref = [hyp.hypothesis_id for hyp in incident.threat_hypotheses]
        
        referenced_incident = ReferencedCorrelatedSecurityIncident(
            incident_id=incident.incident_information.incident_id,
            timeline_reference=timeline_ref,
            attack_graph_reference=graph_ref,
            hypothesis_reference=hypothesis_ref,
            confidence_reference=incident.confidence_assessment.overall_confidence
        )

        # 7. Assemble final root model
        assessment = DomainAIAssessment(
            assessment_information=info,
            active_domain_assessments=active_assessments,
            cross_domain_intelligence=intel_list,
            composite_risk_assessment=composite_risk,
            ai_explanation=explanation,
            recommended_actions=recommendations,
            referenced_correlated_security_incident=referenced_incident
        )

        logger.info(f"Final DomainAIAssessment {assessment_id} assembled successfully.")
        return assessment
