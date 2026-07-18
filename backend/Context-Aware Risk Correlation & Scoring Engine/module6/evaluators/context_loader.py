from typing import Dict, Any, Optional
from module6.interfaces import IContextLoader
from module6.schemas.domain_ai_assessment import DomainAIAssessment

class ContextLoader(IContextLoader):
    def load_context(self, assessment: DomainAIAssessment, external_context: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Loads context information. If external_context is missing, we would typically load from DBs here.
        For this engine, we merge external_context if provided, else return empty or default context.
        """
        raw_context = {}
        if external_context:
            raw_context.update(external_context)
            
        # In a real environment, this is where you'd query CRM, CMDB, etc., using assessment.incident_id or similar.
        return raw_context
