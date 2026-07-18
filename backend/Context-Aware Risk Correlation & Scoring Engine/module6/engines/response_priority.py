from typing import Dict, Any, Tuple
from module6.schemas.unified_risk_assessment import ResponsePriority

class ResponsePriorityEngine:
    def evaluate_response_priority(self, priority: str) -> Tuple[ResponsePriority, Dict[str, Any]]:
        trace = {"input_priority": priority}
        
        if priority == "P1":
            resp = ResponsePriority(
                recommended_response_level="Critical/Immediate",
                response_sla="15 Minutes",
                response_urgency="Immediate",
                automation_eligible=False
            )
        elif priority == "P2":
            resp = ResponsePriority(
                recommended_response_level="High",
                response_sla="1 Hour",
                response_urgency="High",
                automation_eligible=True
            )
        elif priority == "P3":
            resp = ResponsePriority(
                recommended_response_level="Medium",
                response_sla="4 Hours",
                response_urgency="Medium",
                automation_eligible=True
            )
        else: # P4
            resp = ResponsePriority(
                recommended_response_level="Low/Info",
                response_sla="24 Hours",
                response_urgency="Low",
                automation_eligible=True
            )
            
        trace["output"] = resp.model_dump()
        return resp, trace
