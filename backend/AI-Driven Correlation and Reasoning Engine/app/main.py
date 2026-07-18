import sys
import os
import types

# Inject virtual module 'module4' to resolve absolute imports during uvicorn/fastapi execution
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if 'module4' not in sys.modules:
    module4 = types.ModuleType('module4')
    module4.__path__ = [project_root]
    sys.modules['module4'] = module4

import logging
from typing import List, Optional, Union
from fastapi import FastAPI, HTTPException, status
from fastapi.responses import JSONResponse
from module4.app.models.models import SecurityGraphEvent, CorrelatedSecurityIncident
from module4.app.services.correlation_service import CorrelationService
from module4.app.core.container import container
from module4.app.exceptions.exceptions import (
    InvalidSecurityGraphEventException,
    CorrelationException,
    RepositoryException
)
from module4.app.configuration.config import settings

# Setup logging
logging.basicConfig(
    level=settings.LOG_LEVEL,
    format='{"timestamp": "%(asctime)s", "name": "%(name)s", "level": "%(levelname)s", "message": "%(message)s"}' if settings.STRUCTURED_JSON_LOGGING else '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger("FALCON.Module4.API")

app = FastAPI(
    title=settings.API_TITLE,
    version=settings.API_VERSION,
    description="Module 4 of the FALCON platform - AI-Driven Correlation & Reasoning Engine"
)

correlation_service = CorrelationService()

@app.exception_handler(InvalidSecurityGraphEventException)
async def invalid_event_handler(request, exc: InvalidSecurityGraphEventException):
    logger.warning(f"Invalid SecurityGraphEvent input: {exc.message}")
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"error": "InvalidSecurityGraphEvent", "detail": exc.message}
    )

@app.exception_handler(CorrelationException)
async def correlation_error_handler(request, exc: CorrelationException):
    logger.error(f"Correlation pipeline failure: {exc.message}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"error": "CorrelationPipelineFailure", "detail": exc.message}
    )

@app.exception_handler(RepositoryException)
async def repository_error_handler(request, exc: RepositoryException):
    logger.error(f"Incident repository failure: {exc.message}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"error": "RepositoryFailure", "detail": exc.message}
    )

# --- ENDPOINTS ---

@app.get("/health", tags=["Utility"])
def health_check():
    """
    Simple health check endpoint.
    """
    return {"status": "healthy", "module": "Module 4 - AI-Driven Correlation"}

@app.post(
    "/api/v1/correlate",
    response_model=CorrelatedSecurityIncident,
    status_code=status.HTTP_201_CREATED,
    summary="Correlate one or more SecurityGraphEvents into a Security Incident"
)
async def correlate_events(input_data: Union[SecurityGraphEvent, List[SecurityGraphEvent]]):
    """
    Accepts either a single SecurityGraphEvent or a list of SecurityGraphEvents,
    validates the input, runs the AI reasoning/correlation pipeline, and returns
    the resulting CorrelatedSecurityIncident.
    """
    if isinstance(input_data, SecurityGraphEvent):
        event_list = [input_data]
    else:
        event_list = input_data

    if not event_list:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Request body must contain at least one SecurityGraphEvent."
        )

    incident = await correlation_service.correlate_events(event_list)
    return incident

@app.get(
    "/api/v1/incidents",
    response_model=List[CorrelatedSecurityIncident],
    summary="Retrieve all correlated security incidents"
)
async def list_incidents(entity: Optional[str] = None, incident_type: Optional[str] = None):
    """
    Lists all security incidents currently stored in the repository.
    Supports optional filters for primary entity or incident type.
    """
    repo = container.incident_repository
    if entity:
        return repo.search_by_entity(entity)
    elif incident_type:
        return repo.search_by_type(incident_type)
    return repo.list_all()

@app.get(
    "/api/v1/incidents/{incident_id}",
    response_model=CorrelatedSecurityIncident,
    summary="Retrieve a specific security incident by ID"
)
async def get_incident(incident_id: str):
    """
    Retrieves a single security incident from the repository using its unique incident_id.
    """
    repo = container.incident_repository
    incident = repo.get(incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security incident with ID '{incident_id}' not found."
        )
    return incident
