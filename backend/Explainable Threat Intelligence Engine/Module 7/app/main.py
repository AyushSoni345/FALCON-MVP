import logging
from fastapi import FastAPI
from app.config.settings import settings
from app.api.router import router as api_router

# Setup Logging
logging.basicConfig(
    level=settings.log_level.upper(),
    format=(
        '{"timestamp": "%(asctime)s", "name": "%(name)s", "level": "%(levelname)s", "message": "%(message)s"}'
        if settings.structured_json_logging
        else '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
    )
)
logger = logging.getLogger("FALCON.Module7.Application")

# Initialize FastAPI App
app = FastAPI(
    title=settings.api_title,
    version=settings.api_version,
    description="Module 7 of the FALCON platform - Explainable Threat Intelligence Engine"
)

# Register API Router
app.include_router(api_router, prefix="/api/v1")

@app.get("/health", tags=["Utility"])
def health_check():
    """
    Lightweight health check endpoint for monitoring deployment status.
    """
    logger.debug("Health check invoked")
    return {
        "status": "healthy",
        "module": "Module 7 - Explainable Threat Intelligence Engine",
        "version": settings.api_version
    }
