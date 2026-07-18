import logging
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
from app.exceptions.exceptions import InvalidRiskAssessmentException, ReportGenerationException
from app.models.requests import UnifiedRiskAssessment
from app.models.responses import ExplainableThreatReport
from app.validators.validation import validate_risk_assessment
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

logger = logging.getLogger("FALCON.Module7.API.Router")

router = APIRouter()

# Dependency Providers
def get_template_manager() -> ReportTemplateManager:
    return ReportTemplateManager()

def get_formatter() -> ReportFormatter:
    return ReportFormatter()

def get_assembly_service(
    templates: ReportTemplateManager = Depends(get_template_manager),
    formatter: ReportFormatter = Depends(get_formatter)
) -> ReportAssemblyService:
    exec_summary_gen = ExecutiveSummaryGenerator(templates, formatter)
    narrative_builder = IncidentNarrativeBuilder(templates, formatter)
    rca_engine = RootCauseAnalysisEngine(templates, formatter)
    evidence_trace_engine = EvidenceTraceEngine(templates, formatter)
    ai_reasoning_engine = ExplainableAIReasoningEngine(templates, formatter)
    timeline_gen = HumanReadableTimelineGenerator(templates, formatter)
    guidance_engine = InvestigationGuidanceEngine(templates, formatter)
    decision_support_gen = AnalystDecisionSupportGenerator(templates, formatter)

    return ReportAssemblyService(
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

latest_report: ExplainableThreatReport = None

@router.get(
    "/explain/latest",
    response_model=ExplainableThreatReport,
    response_class=JSONResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Latest Explainable Threat Report"
)
async def get_latest_explanation():
    if latest_report is None:
        raise HTTPException(status_code=404, detail="No threat report generated yet.")
    return JSONResponse(status_code=status.HTTP_200_OK, content=jsonable_encoder(latest_report))

@router.post(
    "/explain",
    response_model=ExplainableThreatReport,
    response_class=JSONResponse,
    status_code=status.HTTP_200_OK,
    summary="Generate Explainable Threat Report",
    description="Takes a UnifiedRiskAssessment from Module 6, runs explainability templates, and returns the assembled ExplainableThreatReport."
)
async def generate_explanation(
    assessment: UnifiedRiskAssessment,
    assembly_service: ReportAssemblyService = Depends(get_assembly_service)
):
    global latest_report
    try:
        # Step 1: Input / Business Validation
        validate_risk_assessment(assessment)
        
        # Step 2: Invoke sequential report generation workflow
        report = await assembly_service.assemble_report(assessment)
        
        # Cache for dashboard
        latest_report = report
        
        # Step 3: Serialize output cleanly (nested validation done by Pydantic response_model)
        content = jsonable_encoder(report)
        return JSONResponse(status_code=status.HTTP_200_OK, content=content)
        
    except InvalidRiskAssessmentException as exc:
        logger.warning(f"Validation failure for UnifiedRiskAssessment: {exc.message}")
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": "ValidationError", "detail": exc.message}
        )
    except ReportGenerationException as exc:
        logger.error(f"Report generation failure: {exc.message}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": "ReportGenerationError", "detail": exc.message}
        )
    except Exception as e:
        logger.error(f"Unexpected exception during explainability workflow: {str(e)}", exc_info=True)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": "InternalServerError", "detail": str(e)}
        )
