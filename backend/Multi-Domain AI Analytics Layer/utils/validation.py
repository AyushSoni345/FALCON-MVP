import logging
from module5.models.input.incident import CorrelatedSecurityIncident
from module5.exceptions.exceptions import InvalidIncidentException

logger = logging.getLogger("FALCON.Module5.Validation")

def validate_incident(incident: CorrelatedSecurityIncident) -> None:
    """
    Validates that the input CorrelatedSecurityIncident has all required fields
    needed for Module 5 processing. Raises InvalidIncidentException if invalid.
    """
    logger.debug(f"Starting validation for incident ID: {incident.incident_information.incident_id if incident.incident_information else 'UNKNOWN'}")

    if not incident.incident_information or not incident.incident_information.incident_id:
        raise InvalidIncidentException("Missing incident_id in incident_information.")

    if not incident.incident_information.incident_type:
        raise InvalidIncidentException("Missing incident_type in incident_information.")

    if not incident.incident_timeline or len(incident.incident_timeline) == 0:
        raise InvalidIncidentException("Incident timeline must contain at least one step.")

    for i, step in enumerate(incident.incident_timeline):
        if not step.event_uuid:
            raise InvalidIncidentException(f"Timeline step sequence {step.sequence_number or i} is missing event_uuid.")

    if not incident.confidence_assessment:
        raise InvalidIncidentException("Missing confidence_assessment.")

    if not incident.attack_graph:
        raise InvalidIncidentException("Missing attack_graph.")

    if not incident.ai_reasoning:
        raise InvalidIncidentException("Missing ai_reasoning.")

    logger.info(f"Incident {incident.incident_information.incident_id} successfully validated.")
