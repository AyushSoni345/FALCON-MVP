import uuid
from datetime import datetime, timezone
import logging
from app.exceptions.exceptions import ReportGenerationException
from app.templates.manager import ReportTemplateManager
from app.formatters.formatter import ReportFormatter
from app.generators.executive_summary import ExecutiveSummaryGenerator
from app.generators.incident_narrative import IncidentNarrativeBuilder
from app.generators.root_cause import RootCauseAnalysisEngine
from app.generators.evidence_trace import EvidenceTraceEngine
from app.generators.ai_reasoning import ExplainableAIReasoningEngine
from app.generators.timeline import HumanReadableTimelineGenerator
from app.generators.investigation_guidance import InvestigationGuidanceEngine
from app.generators.decision_support import AnalystDecisionSupportGenerator
from app.models.requests import UnifiedRiskAssessment
from app.models.enums import ReportStatus
from app.models.responses import (
    ReportInformation,
    ReferencedUnifiedRiskAssessment,
    ExplainableThreatReport
)

logger = logging.getLogger("FALCON.Module7.AssemblyService")

class ReportAssemblyService:
    """
    Orchestrates the deterministic sequential pipeline to generate
    an ExplainableThreatReport from a UnifiedRiskAssessment.
    """

    def __init__(
        self,
        template_manager: ReportTemplateManager,
        formatter: ReportFormatter,
        executive_summary_gen: ExecutiveSummaryGenerator,
        narrative_builder: IncidentNarrativeBuilder,
        rca_engine: RootCauseAnalysisEngine,
        evidence_trace_engine: EvidenceTraceEngine,
        ai_reasoning_engine: ExplainableAIReasoningEngine,
        timeline_gen: HumanReadableTimelineGenerator,
        guidance_engine: InvestigationGuidanceEngine,
        decision_support_gen: AnalystDecisionSupportGenerator
    ):
        self.templates = template_manager
        self.formatter = formatter
        self.executive_summary_gen = executive_summary_gen
        self.narrative_builder = narrative_builder
        self.rca_engine = rca_engine
        self.evidence_trace_engine = evidence_trace_engine
        self.ai_reasoning_engine = ai_reasoning_engine
        self.timeline_gen = timeline_gen
        self.guidance_engine = guidance_engine
        self.decision_support_gen = decision_support_gen

    async def assemble_report(self, assessment: UnifiedRiskAssessment) -> ExplainableThreatReport:
        try:
            info = assessment.assessment_information
            logger.info(f"Starting report assembly for risk assessment ID: {info.risk_assessment_id}")

            # Step 1: Report Metadata Generation
            report_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, info.risk_assessment_id))
            report_timestamp = info.timestamp
            
            logger.debug("Generating report metadata")
            report_info = ReportInformation(
                report_id=report_id,
                risk_assessment_id=info.risk_assessment_id,
                incident_id=info.incident_id,
                report_timestamp=report_timestamp,
                report_version="1.0.0",
                report_status=ReportStatus.FINAL
            )

            # Step 2: Generate report sections sequentially
            logger.debug("Generating Executive Summary")
            exec_summary = self.executive_summary_gen.generate(assessment)

            logger.debug("Generating Incident Narrative")
            narrative = self.narrative_builder.generate(assessment)

            logger.debug("Generating Root Cause Analysis")
            rca = self.rca_engine.generate(assessment)

            logger.debug("Generating Evidence Chain")
            evidence_chain = self.evidence_trace_engine.generate(assessment)

            logger.debug("Generating Explainable AI Reasoning")
            ai_reasoning = self.ai_reasoning_engine.generate(assessment)

            logger.debug("Generating Human-Readable Timeline")
            timeline = self.timeline_gen.generate(assessment)

            logger.debug("Generating Investigation Guidance")
            guidance = self.guidance_engine.generate(assessment)

            logger.debug("Generating Analyst Decision Support")
            decision_support = self.decision_support_gen.generate(assessment)

            # Step 3: Attach Referenced Unified Risk Assessment
            logger.debug("Attaching referenced Unified Risk Assessment")
            referenced_ura = ReferencedUnifiedRiskAssessment(
                risk_assessment_id=info.risk_assessment_id,
                incident_classification=assessment.incident_classification,
                context_aware_risk_score=assessment.context_aware_risk_score,
                confidence_assessment=assessment.confidence_assessment,
                prioritization_decision=assessment.prioritization_decision,
                response_priority=assessment.response_priority
            )

            # Step 4: Assemble Complete Report
            logger.debug("Assembling complete report components")
            report = ExplainableThreatReport(
                report_information=report_info,
                executive_summary=exec_summary,
                incident_narrative=narrative,
                root_cause_analysis=rca,
                evidence_chain=evidence_chain,
                explainable_ai_reasoning=ai_reasoning,
                human_readable_timeline=timeline,
                investigation_guidance=guidance,
                analyst_decision_support=decision_support,
                referenced_unified_risk_assessment=referenced_ura
            )

            logger.info(f"Successfully assembled report {report_id} for incident {info.incident_id}")
            return report

        except Exception as e:
            logger.error(f"Failed to assemble Explainable Threat Report: {str(e)}", exc_info=True)
            raise ReportGenerationException(f"Error during report assembly pipeline: {str(e)}")
