from datetime import timedelta
from app.generators.base import BaseGenerator
from app.models.requests import UnifiedRiskAssessment
from app.models.responses import HumanReadableTimeline, HumanReadableTimelineEntry

class HumanReadableTimelineGenerator(BaseGenerator):
    """Generates the Human Readable Timeline section of the report."""

    def generate(self, assessment: UnifiedRiskAssessment) -> HumanReadableTimeline:
        info = assessment.assessment_information
        ref_m5 = assessment.referenced_domain_ai_assessment

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

        # Reconstruct logical timeline milestones
        entries = []

        # Milestone 1: Incident detected
        desc1 = self.templates.get_timeline_entry_desc(
            sequence_number=1,
            action="Incident detected",
            entity=info.primary_entity,
            confidence=assessment.confidence_assessment.ai_confidence
        )
        sig1 = self.templates.get_timeline_entry_sig(action="Incident detected")
        entries.append(HumanReadableTimelineEntry(
            timestamp=info.incident_start_time,
            description=desc1,
            significance=sig1
        ))

        # Milestone 2: Risk assessment performed
        mid_time = info.incident_start_time + timedelta(seconds=info.incident_duration / 2)
        desc2 = self.templates.get_timeline_entry_desc(
            sequence_number=2,
            action="Risk assessment performed",
            entity=f"DomainEngines({', '.join(sorted_domains)})",
            confidence=assessment.confidence_assessment.overall_confidence
        )
        sig2 = self.templates.get_timeline_entry_sig(action="Risk assessment performed")
        entries.append(HumanReadableTimelineEntry(
            timestamp=mid_time,
            description=desc2,
            significance=sig2
        ))

        # Milestone 3: Final business-aware risk established
        desc3 = self.templates.get_timeline_entry_desc(
            sequence_number=3,
            action="Final business-aware risk established",
            entity="Module_6_Risk_Engine",
            confidence=assessment.confidence_assessment.evidence_strength
        )
        
        # risk_level is string
        risk_lvl_str = assessment.context_aware_risk_score.risk_level
        if hasattr(risk_lvl_str, "value"):
            risk_lvl_str = risk_lvl_str.value

        sig3 = f"Incident score aggregated to {assessment.context_aware_risk_score.unified_risk_score:.1f} (Level: {str(risk_lvl_str)})."
        entries.append(HumanReadableTimelineEntry(
            timestamp=info.incident_end_time,
            description=desc3,
            significance=sig3
        ))

        return HumanReadableTimeline(entries=entries)
