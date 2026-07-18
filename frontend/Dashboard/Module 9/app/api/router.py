import logging
import os
import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, status, Body
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder

from app.schemas.input import IncidentResponseLearningPackage
from app.schemas.output import SecurityOperationsDashboard
from app.models.enums import DashboardMode, IncidentStatus
from app.models.dashboard import (
    DashboardInformation,
    LiveOperationsConsole,
    IncidentMonitoringWorkspace,
    SecurityKnowledgeGraphVisualizer,
    ExplainableThreatIntelligenceWorkspace,
    ResponseOperationsWorkspace,
    ContinuousLearningWorkspace,
    ExecutiveOperationalAnalytics,
    AnalystInteractionWorkspace,
    ReferencedIncidentResponseLearningPackage
)
from app.validators.irlp_validator import validate_irlp
from app.exceptions.exceptions import (
    DashboardException,
    DashboardNotFoundException,
    IRLPValidationException,
    ReferenceConflictException,
    InvalidDashboardModeException
)
from app.services.dashboard_manager import DashboardManager
from app.services.dashboard_formatter import DashboardFormatter
from app.api.dependencies import get_dashboard_manager
from app.core.examples import SWAGGER_EXAMPLES

logger = logging.getLogger("FALCON.Module9.API.Router")

router = APIRouter(prefix="/dashboard")

@router.get(
    "/workspace",
    response_model=SecurityOperationsDashboard,
    response_class=JSONResponse,
    summary="Get Complete Dashboard Workspace",
    description="Fetches live data from backend APIs (M3, M8) and compiles the full workspace object."
)
async def get_dashboard_workspace(
    manager: DashboardManager = Depends(get_dashboard_manager)
):
    m8_port = os.environ.get("RESPONSE_PORT", 8008)
    m3_port = os.environ.get("GRAPH_PORT", 8003)
    
    async with httpx.AsyncClient() as client:
        try:
            # Fetch latest package from M8
            pkg_resp = await client.get(f"http://127.0.0.1:{m8_port}/response/latest", timeout=5.0)
            if pkg_resp.status_code != 200:
                raise HTTPException(status_code=503, detail="Backend Module 8 not ready or no package available.")
            
            pkg_data = pkg_resp.json()
            package = IncidentResponseLearningPackage.model_validate(pkg_data)
            
            # Fetch latest graph from M3
            graph_resp = await client.get(f"http://127.0.0.1:{m3_port}/graph/latest", timeout=5.0)
            graph_data = graph_resp.json() if graph_resp.status_code == 200 else None
            
            # Build workspace
            dashboard = manager.load_dashboard(package, mode=DashboardMode.LIVE, refresh_interval=30)
            
            if graph_data and "security_knowledge_graph_visualizer" in graph_data:
                dashboard.security_knowledge_graph_visualizer = SecurityKnowledgeGraphVisualizer.model_validate(
                    graph_data["security_knowledge_graph_visualizer"]
                )
                
            content = DashboardFormatter.format_dashboard(dashboard)
            return JSONResponse(status_code=status.HTTP_200_OK, content=content)
            
        except httpx.RequestError as e:
            logger.error(f"Failed to communicate with backend: {str(e)}")
            raise HTTPException(status_code=503, detail="Backend connection failed")

@router.post("/analyst/action")
async def unified_analyst_action(
    payload: dict = Body(...)
):
    m8_port = os.environ.get("RESPONSE_PORT", 8008)
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(f"http://127.0.0.1:{m8_port}/feedback", json=payload, timeout=5.0)
            if resp.status_code != 200:
                raise HTTPException(status_code=resp.status_code, detail=resp.text)
            return resp.json()
        except httpx.RequestError as e:
            logger.error(f"Failed to communicate with Module 8: {str(e)}")
            raise HTTPException(status_code=503, detail="Backend connection failed")



@router.post(
    "/load",
    response_model=SecurityOperationsDashboard,
    response_class=JSONResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Load Dashboard Session",
    description="Validates the incoming Incident Response & Learning Package (IRLP), registers a new dashboard session, and compiles the workspaces.",
    responses={
        201: {"description": "Dashboard session loaded successfully"},
        409: {"description": "Reference conflict detected"},
        422: {"description": "Unprocessable content due to schema validation failures"}
    }
)
async def load_dashboard(
    package: IncidentResponseLearningPackage = Body(
        ...,
        openapi_examples=SWAGGER_EXAMPLES
    ),
    mode: DashboardMode = Query(DashboardMode.LIVE, description="Dashboard viewing mode (Live, Historical, Investigation)"),
    refresh_interval: int = Query(30, description="UI synchronization refresh frequency in seconds"),
    manager: DashboardManager = Depends(get_dashboard_manager)
):
    try:
        # Step 1: Input Validation
        validate_irlp(package)

        # Step 2: Build & load dashboard
        dashboard = manager.load_dashboard(package, mode=mode, refresh_interval=refresh_interval)

        # Step 3: Format stable JSON response
        content = DashboardFormatter.format_dashboard(dashboard)
        return JSONResponse(status_code=status.HTTP_201_CREATED, content=content)

    except (IRLPValidationException, InvalidDashboardModeException) as exc:
        logger.warning(f"Validation failed: {exc.message}")
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=exc.message)
    except ReferenceConflictException as exc:
        logger.warning(f"Reference conflict: {exc.message}")
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=exc.message)
    except Exception as e:
        logger.error(f"Failed to load dashboard: {str(e)}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Unexpected load error: {str(e)}")


@router.get(
    "/{dashboard_id}",
    response_model=SecurityOperationsDashboard,
    response_class=JSONResponse,
    summary="Get Dashboard Session",
    description="Retrieves the full dashboard session state by ID."
)
async def get_dashboard(
    dashboard_id: str,
    manager: DashboardManager = Depends(get_dashboard_manager)
):
    try:
        dashboard = manager.get_dashboard(dashboard_id)
        content = DashboardFormatter.format_dashboard(dashboard)
        return JSONResponse(status_code=status.HTTP_200_OK, content=content)
    except DashboardNotFoundException as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=exc.message)


@router.get(
    "/{dashboard_id}/refresh",
    response_model=SecurityOperationsDashboard,
    response_class=JSONResponse,
    summary="Refresh Dashboard Visualization",
    description="Reloads and syncs visual parameters without regenerating core AI/SOAR responses."
)
async def refresh_dashboard(
    dashboard_id: str,
    manager: DashboardManager = Depends(get_dashboard_manager)
):
    try:
        dashboard = manager.refresh_dashboard(dashboard_id)
        content = DashboardFormatter.format_dashboard(dashboard)
        return JSONResponse(status_code=status.HTTP_200_OK, content=content)
    except DashboardNotFoundException as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=exc.message)


@router.get(
    "/{dashboard_id}/live",
    response_model=LiveOperationsConsole,
    summary="Get Live Operations Console Workspace",
    description="Returns live operations stats, priority metrics and health state (Workspace 2)."
)
async def get_live_workspace(
    dashboard_id: str,
    manager: DashboardManager = Depends(get_dashboard_manager)
):
    try:
        dashboard = manager.get_dashboard(dashboard_id)
        return JSONResponse(status_code=status.HTTP_200_OK, content=jsonable_encoder(dashboard.live_operations_console))
    except DashboardNotFoundException as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=exc.message)


@router.get(
    "/{dashboard_id}/incident-monitoring",
    response_model=IncidentMonitoringWorkspace,
    summary="Get Incident Monitoring Workspace",
    description="Returns incident logs list and detailed monitoring parameter of selected incident (Workspace 3)."
)
async def get_incidents_workspace(
    dashboard_id: str,
    manager: DashboardManager = Depends(get_dashboard_manager)
):
    try:
        dashboard = manager.get_dashboard(dashboard_id)
        return JSONResponse(status_code=status.HTTP_200_OK, content=jsonable_encoder(dashboard.incident_monitoring_workspace))
    except DashboardNotFoundException as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=exc.message)


@router.get(
    "/{dashboard_id}/knowledge-graph",
    response_model=SecurityKnowledgeGraphVisualizer,
    summary="Get Security Knowledge Graph Visualizer Workspace",
    description="Returns the visual topology structure representing security nodes and relations (Workspace 4)."
)
async def get_graph_workspace(
    dashboard_id: str,
    manager: DashboardManager = Depends(get_dashboard_manager)
):
    try:
        dashboard = manager.get_dashboard(dashboard_id)
        return JSONResponse(status_code=status.HTTP_200_OK, content=jsonable_encoder(dashboard.security_knowledge_graph_visualizer))
    except DashboardNotFoundException as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=exc.message)


@router.get(
    "/{dashboard_id}/threat-intelligence",
    response_model=ExplainableThreatIntelligenceWorkspace,
    summary="Get Explainable Threat Intelligence Workspace",
    description="Returns the explainable root-cause threat intelligence report metadata (Workspace 5)."
)
async def get_threat_intel_workspace(
    dashboard_id: str,
    manager: DashboardManager = Depends(get_dashboard_manager)
):
    try:
        dashboard = manager.get_dashboard(dashboard_id)
        return JSONResponse(status_code=status.HTTP_200_OK, content=jsonable_encoder(dashboard.explainable_threat_intelligence_workspace))
    except DashboardNotFoundException as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=exc.message)


@router.get(
    "/{dashboard_id}/response-operations",
    response_model=ResponseOperationsWorkspace,
    summary="Get Response Operations Workspace",
    description="Returns containment status tracker, SOAR orchestrator state, playbooks logs (Workspace 6)."
)
async def get_response_workspace(
    dashboard_id: str,
    manager: DashboardManager = Depends(get_dashboard_manager)
):
    try:
        dashboard = manager.get_dashboard(dashboard_id)
        return JSONResponse(status_code=status.HTTP_200_OK, content=jsonable_encoder(dashboard.response_operations_workspace))
    except DashboardNotFoundException as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=exc.message)


@router.get(
    "/{dashboard_id}/continuous-learning",
    response_model=ContinuousLearningWorkspace,
    summary="Get Continuous Learning Workspace",
    description="Returns retraining candidates queue, feedback metrics and optimization target models (Workspace 7)."
)
async def get_learning_workspace(
    dashboard_id: str,
    manager: DashboardManager = Depends(get_dashboard_manager)
):
    try:
        dashboard = manager.get_dashboard(dashboard_id)
        return JSONResponse(status_code=status.HTTP_200_OK, content=jsonable_encoder(dashboard.continuous_learning_workspace))
    except DashboardNotFoundException as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=exc.message)


@router.get(
    "/{dashboard_id}/executive-analytics",
    response_model=ExecutiveOperationalAnalytics,
    summary="Get Executive & Operational Analytics Workspace",
    description="Returns incident timeline trends, workloads, and operational KPIs (Workspace 8)."
)
async def get_analytics_workspace(
    dashboard_id: str,
    manager: DashboardManager = Depends(get_dashboard_manager)
):
    try:
        dashboard = manager.get_dashboard(dashboard_id)
        return JSONResponse(status_code=status.HTTP_200_OK, content=jsonable_encoder(dashboard.executive_operational_analytics))
    except DashboardNotFoundException as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=exc.message)


@router.get(
    "/{dashboard_id}/analyst-workspace",
    response_model=AnalystInteractionWorkspace,
    summary="Get Analyst Interaction Workspace",
    description="Returns annotation logs, comments, tags, audit trails and forms (Workspace 9)."
)
async def get_analyst_workspace(
    dashboard_id: str,
    manager: DashboardManager = Depends(get_dashboard_manager)
):
    try:
        dashboard = manager.get_dashboard(dashboard_id)
        return JSONResponse(status_code=status.HTTP_200_OK, content=jsonable_encoder(dashboard.analyst_interaction_workspace))
    except DashboardNotFoundException as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=exc.message)


@router.get(
    "/{dashboard_id}/references",
    response_model=ReferencedIncidentResponseLearningPackage,
    summary="Get Traceability References Workspace",
    description="Returns traceability pointers/references directly to the original Module 8 object schemas (Workspace 10)."
)
async def get_references_workspace(
    dashboard_id: str,
    manager: DashboardManager = Depends(get_dashboard_manager)
):
    try:
        dashboard = manager.get_dashboard(dashboard_id)
        return JSONResponse(status_code=status.HTTP_200_OK, content=jsonable_encoder(dashboard.referenced_incident_response_learning_package))
    except DashboardNotFoundException as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=exc.message)


@router.post(
    "/{dashboard_id}/comments",
    summary="Add Analyst Comment",
    description="Adds a new comment to the Analyst Interaction Workspace."
)
async def add_comment(
    dashboard_id: str,
    author: str = Query(..., description="Author of the comment"),
    text: str = Query(..., description="Text content of the comment"),
    manager: DashboardManager = Depends(get_dashboard_manager)
):
    try:
        comment = manager.add_comment(dashboard_id, author, text)
        return JSONResponse(status_code=status.HTTP_201_CREATED, content=jsonable_encoder(comment))
    except DashboardNotFoundException as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=exc.message)


@router.post(
    "/{dashboard_id}/workflow",
    summary="Perform Workflow Action",
    description="Applies workflow action (Assign, Close, Reopen) to update incident state."
)
async def perform_workflow(
    dashboard_id: str,
    action: str = Query(..., description="Workflow action name (Assign, Close, Reopen)"),
    actor: str = Query(..., description="Analyst user initiating the action"),
    manager: DashboardManager = Depends(get_dashboard_manager)
):
    try:
        new_status = manager.perform_workflow_action(dashboard_id, action, actor)
        return JSONResponse(status_code=status.HTTP_200_OK, content={"status": new_status.value})
    except DashboardNotFoundException as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=exc.message)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.post(
    "/{dashboard_id}/tags",
    summary="Add Dashboard Tag",
    description="Appends a new tag to the Analyst Interaction Workspace incident tags list."
)
async def add_tag(
    dashboard_id: str,
    tag: str = Query(..., description="The tag name to append"),
    manager: DashboardManager = Depends(get_dashboard_manager)
):
    try:
        dashboard = manager.get_dashboard(dashboard_id)
        clean_tag = tag.strip().upper().replace(" ", "_")
        if clean_tag not in dashboard.analyst_interaction_workspace.incident_tags:
            dashboard.analyst_interaction_workspace.incident_tags.append(clean_tag)
        return JSONResponse(status_code=status.HTTP_200_OK, content={"tags": dashboard.analyst_interaction_workspace.incident_tags})
    except DashboardNotFoundException as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=exc.message)
