import os
import uvicorn
from fastapi import FastAPI, HTTPException
from module6.config.manager import ConfigurationManager
from module6.main import setup_app
from module6.schemas.domain_ai_assessment import DomainAIAssessment
from module6.schemas.unified_risk_assessment import UnifiedRiskAssessment

app = FastAPI(
    title="Module 6 - Context-Aware Risk Correlation",
    version="1.0.0"
)

pipeline = None
metrics = None
latest_risk = None

@app.on_event("startup")
def startup_event():
    global pipeline, metrics
    config_dir = os.path.join(os.path.dirname(__file__), "config")
    storage_dir = os.path.join(os.path.dirname(__file__), "storage")
    os.makedirs(storage_dir, exist_ok=True)
    pipeline, metrics = setup_app(config_dir, storage_dir)

@app.get("/health")
def health_check():
    return {
        "service": "Module 6 - Risk Correlation",
        "status": "healthy",
        "version": "1.0.0",
        "uptime": "N/A"
    }

@app.post("/evaluate", response_model=UnifiedRiskAssessment)
def evaluate_risk(assessment: DomainAIAssessment):
    global latest_risk
    if not pipeline:
        raise HTTPException(status_code=500, detail="Pipeline not initialized")
    result = pipeline.process(assessment, {})
    latest_risk = result.unified_risk_assessment
    return latest_risk

@app.get("/evaluate/latest", response_model=UnifiedRiskAssessment)
def get_latest_risk():
    if not latest_risk:
        raise HTTPException(status_code=404, detail="No risk assessment generated yet")
    return latest_risk

if __name__ == "__main__":
    port = int(os.environ.get("RISK_PORT", 8006))
    uvicorn.run(app, host="0.0.0.0", port=port)
