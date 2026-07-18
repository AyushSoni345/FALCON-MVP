from app.generators.base import BaseGenerator
from app.models.requests import UnifiedRiskAssessment
from app.models.responses import EvidenceChain

class EvidenceTraceEngine(BaseGenerator):
    """Generates the Evidence Chain section of the report."""

    def generate(self, assessment: UnifiedRiskAssessment) -> EvidenceChain:
        info = assessment.assessment_information
        eval_sec = assessment.context_evaluation
        sig = assessment.risk_signal_aggregation
        score_sec = assessment.context_aware_risk_score
        conf_sec = assessment.confidence_assessment
        ref_m5 = assessment.referenced_domain_ai_assessment
        prioritization = assessment.prioritization_decision

        # Resolve active domains list
        active_domains = []
        if isinstance(ref_m5.active_domain_assessments, list):
            active_domains = ref_m5.active_domain_assessments
        else:
            act = ref_m5.active_domain_assessments
            if act:
                if getattr(act, "behaviour_assessment", None): active_domains.append("Behaviour")
                if getattr(act, "fraud_assessment", None): active_domains.append("Fraud")
                if getattr(act, "cyber_assessment", None): active_domains.append("Cyber")
                if getattr(act, "quantum_assessment", None): active_domains.append("Quantum")
        sorted_domains = sorted(active_domains)

        # 1. Evidence Sequence
        evidence_sequence = [
            f"1. Risk Signals: Multi-domain assessment analyzed active domains: {', '.join(sorted_domains)} with an aggregated score of {sig.aggregated_score:.1f}.",
            f"2. Business Context: Process '{eval_sec.business_context.business_process}' evaluated with high-net-worth status: {eval_sec.customer_context.high_net_worth_customer}.",
            f"3. Confidence: Overall evaluation confidence calculated at {conf_sec.overall_confidence:.2f} (False Positive Probability: {conf_sec.false_positive_probability:.2f}).",
            f"4. Final Decision: Incident prioritized as level '{prioritization.priority_level}' with escalation status set to {prioritization.escalation_required}.",
            f"5. References: Traced to domain AI assessment reference identifier '{ref_m5.assessment_id}'."
        ]

        # 2. Supporting Events (sorted deterministically)
        supporting_events = []
        for domain, score in sorted(sig.domain_scores.items()):
            weighted = sig.weighted_scores.get(domain, 0.0)
            supporting_events.append(f"Domain '{domain}' risk score: {score:.1f} (Weight contributor: {weighted:.1f})")

        # Resolve cross domain intelligence link
        cdi_list = []
        if isinstance(ref_m5.cross_domain_intelligence, list):
            cdi_list = ref_m5.cross_domain_intelligence
        elif ref_m5.cross_domain_intelligence is not None:
            cdi = ref_m5.cross_domain_intelligence
            desc = (
                f"Source: {cdi.source_domain} -> Target: {cdi.target_domain} "
                f"| Indicator: {cdi.shared_indicator} | Impact: {cdi.impact} "
                f"| Strength: {cdi.correlation_strength:.2f}"
            )
            cdi_list = [desc]

        for intel in sorted(cdi_list):
            supporting_events.append(f"Cross-Domain Intelligence Link: {intel}")

        supporting_events.append(f"Credential exposure risk assessment: {str(eval_sec.data_context.credential_exposure)}")
        supporting_events.append(f"PII exposure risk level: {str(eval_sec.data_context.pii_exposure)}")

        # 3. Graph Paths (sorted deterministically)
        graph_paths = sorted([
            f"Relational Graph Traversal Path: Entity '{info.primary_entity}' -> Payment Channel '{eval_sec.transaction_context.payment_channel}' -> System Host '{str(eval_sec.asset_context.production_system)}'",
            f"Data store reference node: {str(eval_sec.data_context.cryptographic_asset)}"
        ])

        # 4. AI Assessments (deterministic order)
        ai_assessments = [
            f"Assessment Reference ID: {ref_m5.assessment_id}",
            f"Overall AI evaluation confidence score: {conf_sec.ai_confidence:.2f}",
            f"AI explanation summary: Multi-domain AI assessment confirmed threat activity across active domains: {', '.join(sorted_domains)}."
        ]

        # 5. Business Context (deterministic order)
        bus_context = [
            f"Business Process: {eval_sec.business_context.business_process} (Criticality Level: {eval_sec.business_context.business_criticality})",
            f"Service Impact: {eval_sec.business_context.service_impact}",
            f"Overall financial process exposure: {eval_sec.transaction_context.financial_exposure}"
        ]

        return EvidenceChain(
            evidence_sequence=self.formatter.format_list_to_bullets(evidence_sequence),
            supporting_events=self.formatter.format_list_to_bullets(supporting_events),
            graph_paths=self.formatter.format_list_to_bullets(graph_paths),
            ai_assessments=self.formatter.format_list_to_bullets(ai_assessments),
            business_context=self.formatter.format_list_to_bullets(bus_context)
        )
