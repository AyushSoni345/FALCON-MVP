import logging
import os
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from app.core.config import settings
from app.core.logging import setup_logging
from app.api.router import router as api_router

# Setup Logging
setup_logging()
logger = logging.getLogger("FALCON.Module9.Application")

# Initialize FastAPI App
app = FastAPI(
    title=settings.api_title,
    version=settings.api_version,
    description="Module 9 of the FALCON platform - Security Operations Dashboard"
)

# Register API Router
app.include_router(api_router, prefix="/api/v1")

# Mount Static Files
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.get("/", tags=["Dashboard UI"])
def get_dashboard_ui():
    """
    Serves the main enterprise dashboard HTML page.
    """
    index_path = os.path.join(static_dir, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"message": "Dashboard UI files not found. Check app/static directory."}

@app.get("/health", tags=["Utility"])
def health_check():
    """
    Lightweight health check endpoint for monitoring deployment status.
    """
    logger.debug("Health check invoked")
    return {
        "status": "healthy",
        "platform": "FALCON",
        "module": "Module 9 - Security Operations Dashboard",
        "version": settings.api_version
    }
