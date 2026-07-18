import logging
from app.exceptions.exceptions import IRLPValidationException
from app.schemas.input import IncidentResponseLearningPackage

logger = logging.getLogger("FALCON.Module9.Validation")

def validate_irlp(package: IncidentResponseLearningPackage) -> None:
    """
    Performs structural and referential business validation on the incoming
    IncidentResponseLearningPackage. Raises IRLPValidationException if invalid.
    """
    logger.debug("Validating IncidentResponseLearningPackage metadata structure")

    # 1. Structural Checks on top-level structures
    if not package.response_package_info:
        raise IRLPValidationException("response_package_info is required.")
    
    info = package.response_package_info
    if not info.response_package_id or not info.response_package_id.strip():
        raise IRLPValidationException("response_package_id cannot be empty.")
    if not info.report_id or not info.report_id.strip():
        raise IRLPValidationException("report_id cannot be empty in response_package_info.")
    if not info.incident_id or not info.incident_id.strip():
        raise IRLPValidationException("incident_id cannot be empty in response_package_info.")

    # 2. Check child section existence
    if not package.incident_response_plan:
        raise IRLPValidationException("incident_response_plan is required.")
    if not package.response_execution_plan:
        raise IRLPValidationException("response_execution_plan is required.")
    if not package.referenced_threat_report:
        raise IRLPValidationException("referenced_threat_report is required.")

    # 3. Referential ID Consistency
    report = package.referenced_threat_report
    
    if info.report_id != report.report_id:
        raise IRLPValidationException(
            f"Referential mismatch on report_id: package={info.report_id}, report={report.report_id}"
        )

    # 4. Status Checks on SOAR tasks
    for idx, task in enumerate(package.soar_orchestration_tasks):
        if not task.task_id or not task.task_id.strip():
            raise IRLPValidationException(f"SOAR task at index {idx} has an empty task_id.")

    logger.info(f"IRLP Package {info.response_package_id} passed referential validation successfully.")
