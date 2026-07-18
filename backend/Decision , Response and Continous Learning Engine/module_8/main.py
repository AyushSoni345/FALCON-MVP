from typing import Dict, Any
from module_8.services.response_service import ResponseService
from module_8.models.output_models import IncidentResponseLearningPackage

def process_threat_report(etr_payload: Dict[str, Any]) -> IncidentResponseLearningPackage:
    """
    Entry point for Module 8 to process a new ExplainableThreatReport payload.
    """
    service = ResponseService()
    package = service.process_incident(etr_payload)
    return package

def apply_analyst_decision(package: IncidentResponseLearningPackage, etr_payload: Dict[str, Any], analyst_id: str, decision: str, verdict: str, notes: str) -> IncidentResponseLearningPackage:
    """
    Entry point for applying Analyst Feedback to an existing package.
    """
    service = ResponseService()
    etr = service.validation_service.validate_etr(etr_payload)
    updated_package = service.apply_analyst_feedback(
        package=package,
        etr=etr,
        analyst_id=analyst_id,
        decision=decision,
        verdict=verdict,
        notes=notes
    )
    return updated_package
