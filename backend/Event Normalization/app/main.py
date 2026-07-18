from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes import router as api_router
from app.config import settings
from app.logging_config import logger

app = FastAPI(
    title=settings.api_title,
    description=(
        "FALCON Module 2: Event Normalization & Threat Enrichment Layer. "
        "Transforms raw heterogeneous telemetry and banking events into normalized, enriched common schema models."
    ),
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# Enable CORS for cross-module integration (Modules 1 and 3)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register endpoints
app.include_router(api_router)

@app.get("/health", tags=["Utility"])
def health_check():
    return {"status": "healthy", "module": "Module 2 - Event Normalization"}

@app.on_event("startup")
async def startup_event():
    logger.info(
        f"FALCON Module 2 initialized. "
        f"Running mode: {settings.env}. "
        f"Docs available at http://{settings.host}:{settings.port}/docs"
    )

@app.on_event("shutdown")
async def shutdown_event():
    logger.info("FALCON Module 2 shutting down.")
