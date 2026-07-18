import re
from datetime import datetime
from typing import Dict, Any, Tuple, Optional
from pydantic import ValidationError

from Ingestion.models import CommonEnvelope, PAYLOAD_MODELS

# Regular expression to strictly match ISO-8601 UTC format: YYYY-MM-DDTHH:MM:SSZ
# e.g., 2026-07-14T11:30:00Z
ISO_TIMESTAMP_REGEX = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

def validate_event(event_dict: Dict[str, Any]) -> Tuple[bool, str, Optional[CommonEnvelope]]:
    """
    Validates the event schema, envelope fields, timestamp formatting, and event-specific payload.
    Returns (is_valid, error_message, validated_envelope_model).
    """
    # 1. Basic Envelope Validation
    try:
        envelope = CommonEnvelope(**event_dict)
    except ValidationError as e:
        return False, f"Envelope validation failed: {e}", None
    except Exception as e:
        return False, f"Envelope parsing error: {str(e)}", None

    # 2. Envelope Mandatory Fields Empty Check
    for field in ["event_id", "event_type", "source_system", "timestamp", "severity"]:
        val = getattr(envelope, field)
        if not val or (isinstance(val, str) and not val.strip()):
            return False, f"Envelope field '{field}' is mandatory and cannot be empty/whitespace", None

    # 3. Timestamp Validation (Format & Values)
    ts = envelope.timestamp
    if not ISO_TIMESTAMP_REGEX.match(ts):
        return False, f"Timestamp '{ts}' does not match strict ISO-8601 UTC format (YYYY-MM-DDTHH:MM:SSZ)", None
    
    try:
        # Check if it represents a valid calendar date
        datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as e:
        return False, f"Timestamp '{ts}' represents an invalid date: {e}", None

    # 4. Event Type specific validation
    etype = envelope.event_type.lower()
    if etype not in PAYLOAD_MODELS:
        return False, f"Unknown event_type: '{envelope.event_type}'", None

    payload_model = PAYLOAD_MODELS[etype]
    try:
        # Validate specific payload sub-schema
        payload_model(**envelope.raw_payload)
    except ValidationError as e:
        return False, f"Payload validation failed for type '{envelope.event_type}': {e}", None
    except Exception as e:
        return False, f"Payload validation error for type '{envelope.event_type}': {str(e)}", None

    # Check for empty string fields inside raw_payload
    for k, v in envelope.raw_payload.items():
        if isinstance(v, str) and not v.strip():
            # If the payload field is a required field, check if it's empty
            # Note: Optional fields in models can be None or empty. 
            # Pydantic validates type constraints, but empty strings should be checked if needed.
            # We will raise warning or reject if a required string field is empty.
            pass

    return True, "", envelope
