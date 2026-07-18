from app.generators.base import BaseGenerator
from app.models.requests import UnifiedRiskAssessment
from app.models.responses import RootCauseAnalysis

class RootCauseAnalysisEngine(BaseGenerator):
    """Generates the Root Cause Analysis section of the report."""

    def generate(self, assessment: UnifiedRiskAssessment) -> RootCauseAnalysis:
        eval_sec = assessment.context_evaluation
        score_sec = assessment.context_aware_risk_score
        conf_sec = assessment.confidence_assessment
        classification = assessment.incident_classification
        ref_m5 = assessment.referenced_domain_ai_assessment

        # Resolve active domains list
        domains = []
        if isinstance(ref_m5.active_domain_assessments, list):
            domains = ref_m5.active_domain_assessments
        else:
            act = ref_m5.active_domain_assessments
            if act:
                if getattr(act, "behaviour_assessment", None): domains.append("Behaviour")
                if getattr(act, "fraud_assessment", None): domains.append("Fraud")
                if getattr(act, "cyber_assessment", None): domains.append("Cyber")
                if getattr(act, "quantum_assessment", None): domains.append("Quantum")
        active_domains = sorted(domains)
        
        # Deterministically derive probable root cause based on active domains
        if "Behaviour" in active_domains:
            if "Fraud" in active_domains:
                probable_root_cause = "Compromised consumer credentials causing unauthorized high-value transfers."
                triggering_event = f"Anomalous {eval_sec.transaction_context.payment_channel} session authorization matching credential risk profile ({eval_sec.data_context.credential_exposure})."
            else:
                probable_root_cause = "Compromised consumer credentials causing anomalous session logins."
                triggering_event = f"Failed authentication attempt followed by login from untrusted IP ({eval_sec.data_context.credential_exposure})."
        elif "Cyber" in active_domains:
            probable_root_cause = "Unauthorized production endpoint exploitation."
            triggering_event = f"Infrastructure vulnerability exploit attempt targeting production system '{str(eval_sec.asset_context.production_system)}'."
        elif "Quantum" in active_domains:
            probable_root_cause = "Harvest-Now-Decrypt-Later (HNDL) exfiltration of legacy encrypted archives."
            triggering_event = f"Bulk exfiltration request on cryptographic keys archive '{str(eval_sec.data_context.cryptographic_asset)}'."
        else:
            probable_root_cause = "Unusual credential anomalies across multi-domain telemetry endpoints."
            triggering_event = "System baseline activity threshold deviation."

        contributing_factors = [
            f"Customer risk profile rated as '{eval_sec.customer_context.customer_risk_profile}'",
            f"Target production system criticality rated as '{eval_sec.asset_context.asset_criticality}'",
            f"Confidential data exposure profile ({eval_sec.data_context.data_classification})"
        ]
        if eval_sec.customer_context.high_net_worth_customer:
            contributing_factors.append("High Net Worth Customer (HNWI) target account profile")

        # Deterministic sorting of contributing factors
        contributing_factors = sorted(contributing_factors)

        factors_str = ", ".join(contributing_factors)

        # risk_level is string
        risk_lvl_str = score_sec.risk_level
        if hasattr(risk_lvl_str, "value"):
            risk_lvl_str = risk_lvl_str.value

        explanation = self.templates.get_root_cause_explanation(
            probable_root_cause=probable_root_cause,
            triggering_event=triggering_event,
            risk_level=str(risk_lvl_str),
            factors=factors_str,
            impact_summary=classification.operational_impact
        )

        return RootCauseAnalysis(
            probable_root_cause=explanation,
            contributing_factors=self.formatter.format_list_to_bullets(contributing_factors),
            triggering_event=triggering_event,
            impact_summary=classification.operational_impact,
            confidence=conf_sec.overall_confidence
        )
