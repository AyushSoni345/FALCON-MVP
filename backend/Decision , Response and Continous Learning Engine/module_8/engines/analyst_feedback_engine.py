from typing import Optional
from datetime import datetime
from module_8.models.output_models import AnalystValidation
from module_8.utils.helpers import current_timestamp

class AnalystFeedbackEngine:
    def process_feedback(self, decision: str, notes: str, override_reason: Optional[str] = None, timestamp: Optional[datetime] = None) -> AnalystValidation:
        valid_decisions = ["Approved", "Modified", "Rejected"]
        if decision not in valid_decisions:
            raise ValueError(f"Invalid analyst decision. Must be one of {valid_decisions}")
            
        return AnalystValidation(
            analyst_decision=decision,
            validation_notes=notes,
            override_reason=override_reason,
            approval_timestamp=timestamp if timestamp else current_timestamp()
        )
