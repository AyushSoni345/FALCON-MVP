from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse

from Ingestion.core.pipeline import pipeline

app = FastAPI(
    title="FinGuard AI Unified Data Ingestion API",
    description="Module 1: Real-time Event Ingestion Layer",
    version="1.0.0"
)

@app.post("/api/v1/ingest", status_code=status.HTTP_202_ACCEPTED)
async def ingest_endpoint(request: Request):
    """
    Receives incoming banking and cybersecurity events, runs them through the 
    validation, deduplication, and chronology checks pipeline, and saves them.
    """
    try:
        body = await request.json()
    except Exception as e:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"status": "rejected", "error": f"Invalid JSON payload: {e}"}
        )

    # Process through the pipeline
    success, err_msg, success_payload = pipeline.ingest_event(body)
    
    if not success:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"status": "rejected", "error": err_msg}
        )

    return JSONResponse(
        status_code=status.HTTP_202_ACCEPTED,
        content=success_payload
    )

@app.get("/health")
def health_check():
    return {"status": "healthy"}
