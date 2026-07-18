import logging
from fastapi import APIRouter, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
from module5.models.input.incident import CorrelatedSecurityIncident
from module5.models.output.assessment import DomainAIAssessment
from module5.orchestrator.orchestrator import Module5Orchestrator
from module5.exceptions.exceptions import InvalidIncidentException, AnalyticsPipelineException

logger = logging.getLogger("FALCON.Module5.API.Router")

router = APIRouter()
orchestrator = Module5Orchestrator()

@router.post(
    "/analyze",
    response_model=DomainAIAssessment,
    response_class=JSONResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze a Correlated Security Incident across multiple AI domains",
    description="Takes a CorrelatedSecurityIncident from Module 4, runs multi-domain AI analytics, and returns a dynamic DomainAIAssessment."
)
async def analyze_incident(incident: CorrelatedSecurityIncident):
    try:
        assessment = await orchestrator.analyze(incident)
        # Serialize and exclude None to dynamically omit inactive engines
        content = jsonable_encoder(assessment.model_dump(by_alias=False, exclude_none=True))
        return JSONResponse(status_code=status.HTTP_200_OK, content=content)
    except InvalidIncidentException as exc:
        logger.warning(f"Validation failure for incident input: {exc.message}")
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": "ValidationError", "detail": exc.message}
        )
    except AnalyticsPipelineException as exc:
        logger.error(f"Pipeline failure: {exc.message}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": "PipelineError", "detail": exc.message}
        )
    except Exception as e:
        logger.error(f"Unexpected exception during analysis: {str(e)}", exc_info=True)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": "InternalServerError", "detail": str(e)}
        )
