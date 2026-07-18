import sys
import os
import types

# Ensure module5 namespace resolves dynamically
if "module5" not in sys.modules:
    m5_path = os.path.dirname(os.path.abspath(__file__))
    if m5_path.startswith("\\") and len(m5_path) > 2 and m5_path[2] == ":":
        m5_path = m5_path[1:]
    m5_module = types.ModuleType("module5")
    m5_module.__path__ = [m5_path]
    m5_module.__file__ = os.path.join(m5_path, "__init__.py")
    sys.modules["module5"] = m5_module

import logging
from fastapi import FastAPI
from module5.api.router import router as api_router
from module5.config.settings import settings

# Setup logging
logging.basicConfig(
    level=settings.LOG_LEVEL,
    format='{"timestamp": "%(asctime)s", "name": "%(name)s", "level": "%(levelname)s", "message": "%(message)s"}' if settings.STRUCTURED_JSON_LOGGING else '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger("FALCON.Module5.Application")

app = FastAPI(
    title=settings.API_TITLE,
    version=settings.API_VERSION,
    description="Module 5 of the FALCON platform - Multi-Domain AI Analytics Layer"
)

# Register API Router
app.include_router(api_router, prefix="/module5")

@app.get("/health", tags=["Utility"])
def health_check():
    """
    Simple health check endpoint.
    """
    return {"status": "healthy", "module": "Module 5 - Multi-Domain AI Analytics Layer"}
