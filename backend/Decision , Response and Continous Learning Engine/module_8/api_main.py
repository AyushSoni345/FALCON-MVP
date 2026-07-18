import os
import uvicorn
from fastapi import FastAPI, HTTPException
from typing import Dict, Any

from module_8.models.input_models import ExplainableThreatReport
from module_8.models.output_models import IncidentResponseLearningPackage
from module_8.services.response_service import ResponseService

app = FastAPI(
    title="Module 8 - Decision, Response and Continuous Learning",
    version="1.0.0"
)

response_service = ResponseService()
latest_package: IncidentResponseLearningPackage = None
latest_etr: ExplainableThreatReport = None

@app.get("/health")
def health_check():
    return {
        "service": "Module 8 - Decision & Response",
        "status": "healthy",
        "version": "1.0.0"
    }

@app.post("/process", response_model=IncidentResponseLearningPackage)
def process_etr(etr: ExplainableThreatReport):
    global latest_package, latest_etr
    latest_etr = etr
    latest_package = response_service.process_incident(etr.model_dump())
    return latest_package

@app.get("/response/latest", response_model=IncidentResponseLearningPackage)
def get_latest_response():
    if latest_package is None:
        raise HTTPException(status_code=404, detail="No package generated yet.")
    return latest_package

@app.post("/feedback", response_model=IncidentResponseLearningPackage)
def submit_feedback(payload: Dict[str, Any]):
    global latest_package, latest_etr
    if latest_package is None or latest_etr is None:
        raise HTTPException(status_code=400, detail="No active package to apply feedback to.")
        
    decision = payload.get("decision", "Modified")
    verdict = payload.get("verdict", "True Positive")
    notes = payload.get("notes", "")
    analyst_id = payload.get("analyst_id", "soc.analyst")
    
    updated_package = response_service.apply_analyst_feedback(
        package=latest_package,
        etr=latest_etr,
        analyst_id=analyst_id,
        decision=decision,
        verdict=verdict,
        notes=notes
    )
    latest_package = updated_package
    return latest_package

if __name__ == "__main__":
    port = int(os.environ.get("RESPONSE_PORT", 8008))
    uvicorn.run(app, host="0.0.0.0", port=port)
