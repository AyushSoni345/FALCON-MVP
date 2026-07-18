from typing import Dict, Any
from pydantic import ValidationError
from module_8.models.input_models import ExplainableThreatReport
from module_8.utils.logger import get_logger

logger = get_logger(__name__)

SUPPORTED_REPORT_VERSIONS = ["1.0", "1.0.0"]

class ValidationService:
    def validate_etr(self, payload: Dict[str, Any]) -> ExplainableThreatReport:
        # Check explicit version support first to avoid silent contract breakage
        report_info = payload.get("report_information", {})
        version = report_info.get("report_version")
        if version not in SUPPORTED_REPORT_VERSIONS:
            raise ValueError(f"Unsupported report_version: {version}. Supported versions: {SUPPORTED_REPORT_VERSIONS}")
            
        try:
            etr = ExplainableThreatReport(**payload)
            logger.info(f"Successfully validated ETR for report_id: {etr.report_information.report_id}")
            return etr
        except ValidationError as e:
            logger.error(f"Validation failed for ETR: {str(e)}")
            raise ValueError(f"Invalid ExplainableThreatReport schema: {str(e)}")
