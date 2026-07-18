import pytest
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
from app.services.assembly import ReportAssemblyService
from app.models.enums import ReportStatus

@pytest.mark.asyncio
async def test_report_assembly_service_pipeline(mock_assessment):
    templates = ReportTemplateManager()
    formatter = ReportFormatter()
    
    exec_summary_gen = ExecutiveSummaryGenerator(templates, formatter)
    narrative_builder = IncidentNarrativeBuilder(templates, formatter)
    rca_engine = RootCauseAnalysisEngine(templates, formatter)
    evidence_trace_engine = EvidenceTraceEngine(templates, formatter)
    ai_reasoning_engine = ExplainableAIReasoningEngine(templates, formatter)
    timeline_gen = HumanReadableTimelineGenerator(templates, formatter)
    guidance_engine = InvestigationGuidanceEngine(templates, formatter)
    decision_support_gen = AnalystDecisionSupportGenerator(templates, formatter)

    service = ReportAssemblyService(
        template_manager=templates,
        formatter=formatter,
        executive_summary_gen=exec_summary_gen,
        narrative_builder=narrative_builder,
        rca_engine=rca_engine,
        evidence_trace_engine=evidence_trace_engine,
        ai_reasoning_engine=ai_reasoning_engine,
        timeline_gen=timeline_gen,
        guidance_engine=guidance_engine,
        decision_support_gen=decision_support_gen
    )

    report = await service.assemble_report(mock_assessment)
    
    assert report.report_information.risk_assessment_id == "URA-20260715-0001"
    assert report.report_information.incident_id == "INC-12345"
    assert report.report_information.report_status == ReportStatus.FINAL
    assert report.executive_summary.unified_risk_score == 85.5
    assert len(report.incident_narrative.attack_progression) > 0
    assert report.root_cause_analysis.confidence == 0.85
    assert len(report.evidence_chain.evidence_sequence) == 5
    assert len(report.human_readable_timeline.entries) == 3
    assert report.referenced_unified_risk_assessment.risk_assessment_id == "URA-20260715-0001"
