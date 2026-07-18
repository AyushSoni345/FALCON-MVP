from typing import Any, Dict, List

class ReportTemplateManager:
    """
    Manages and resolves internal text templates for report sections.
    All template strings are populated using deterministic string formatting.
    """

    EXECUTIVE_SUMMARY_OVERVIEW = (
        "A {risk_level}-severity security event classified as '{classification}' was identified "
        "implicating the primary entity '{primary_entity}'. Driven by {primary_cause}, the activity "
        "resulted in a context-aware risk score of {risk_score:.1f}. Given the potential business impact "
        "on '{business_process}' ({business_impact}), this incident has been assigned a priority rating "
        "of '{recommended_priority}' for immediate SOC triage."
    )

    NARRATIVE_SUMMARY = (
        "A security event classified as '{classification}' was identified involving the primary entity '{primary_entity}'. "
        "The anomalous sequence was initiated at {start_time} and persisted over a duration of {duration:.2f} seconds, "
        "implicating {assets_count} critical corporate or customer asset(s)."
    )

    NARRATIVE_PROGRESSION = (
        "The incident began when activity associated with entity '{primary_entity}' was initiated "
        "via payment channel '{entry_point}'. Subsequently, the multi-domain analytics engine activated "
        "evaluations for the active domains: {timeline_summary}. The activity later progressed to "
        "destination asset '{exit_point}', ultimately resulting in a security escalation at {end_time}."
    )

    ROOT_CAUSE_EXPLANATION = (
        "Based on the analytical facts provided in the risk assessment, the probable root cause of the incident "
        "is identified as '{probable_root_cause}', initially triggered by '{triggering_event}'. "
        "This led to a {risk_level} risk level designation under the following contributing factors: {factors}. "
        "The resulting operational impact is established as: {impact_summary}."
    )

    AI_REASONING_SUMMARY = (
        "The multi-domain AI assessment concluded with the classification of '{ai_decision_summary}' "
        "at an overall evaluation confidence of {confidence:.2f}. The decision path was primarily "
        "influenced by {steps}. System confidence was strengthened by {supporting}, while it was "
        "counterbalanced by {contradictory}."
    )

    TIMELINE_ENTRY_DESC = (
        "Step {sequence_number}: {action} was executed by entity '{entity}' "
        "with an extraction confidence of {confidence:.2f}."
    )

    TIMELINE_ENTRY_SIG = (
        "Event represents a key milestone ({action}) in the threat progression timeline."
    )

    DECISION_SUPPORT_AUTOMATION = (
        "Based on security orchestration policies, this incident is {status} for automated response playbooks."
    )

    def get_executive_summary_overview(
        self,
        risk_level: str,
        classification: str,
        primary_entity: str,
        primary_cause: str,
        risk_score: float,
        business_process: str,
        business_impact: str,
        recommended_priority: str
    ) -> str:
        return self.EXECUTIVE_SUMMARY_OVERVIEW.format(
            risk_level=risk_level,
            classification=classification,
            primary_entity=primary_entity,
            primary_cause=primary_cause,
            risk_score=risk_score,
            business_process=business_process,
            business_impact=business_impact,
            recommended_priority=recommended_priority
        )

    def get_narrative_summary(self, classification: str, primary_entity: str, start_time: str, duration: float, assets_count: int) -> str:
        return self.NARRATIVE_SUMMARY.format(
            classification=classification,
            primary_entity=primary_entity,
            start_time=start_time,
            duration=duration,
            assets_count=assets_count
        )

    def get_narrative_progression(self, primary_entity: str, entry_action: str, entry_point: str, timeline_summary: str, end_time: str, exit_point: str) -> str:
        return self.NARRATIVE_PROGRESSION.format(
            primary_entity=primary_entity,
            entry_action=entry_action,
            entry_point=entry_point,
            timeline_summary=timeline_summary,
            end_time=end_time,
            exit_point=exit_point
        )

    def get_root_cause_explanation(self, probable_root_cause: str, triggering_event: str, risk_level: str, factors: str, impact_summary: str) -> str:
        return self.ROOT_CAUSE_EXPLANATION.format(
            probable_root_cause=probable_root_cause,
            triggering_event=triggering_event,
            risk_level=risk_level,
            factors=factors,
            impact_summary=impact_summary
        )

    def get_ai_reasoning_summary(self, ai_decision_summary: str, confidence: float, steps: str, supporting: str, contradictory: str) -> str:
        return self.AI_REASONING_SUMMARY.format(
            ai_decision_summary=ai_decision_summary,
            confidence=confidence,
            steps=steps,
            supporting=supporting,
            contradictory=contradictory
        )

    def get_timeline_entry_desc(self, sequence_number: int, action: str, entity: str, confidence: float) -> str:
        return self.TIMELINE_ENTRY_DESC.format(
            sequence_number=sequence_number,
            action=action,
            entity=entity,
            confidence=confidence
        )

    def get_timeline_entry_sig(self, action: str) -> str:
        return self.TIMELINE_ENTRY_SIG.format(action=action)

    def get_automation_recommendation(self, eligible: bool) -> str:
        status = "eligible" if eligible else "not eligible"
        return self.DECISION_SUPPORT_AUTOMATION.format(status=status)
