import logging
from app.exceptions.exceptions import InvalidRiskAssessmentException
from app.models.requests import UnifiedRiskAssessment

logger = logging.getLogger("FALCON.Module7.Validation")

def validate_risk_assessment(assessment: UnifiedRiskAssessment) -> None:
    """
    Performs structural and reference business validation on the incoming
    UnifiedRiskAssessment. Raises InvalidRiskAssessmentException if invalid.
    """
    info = assessment.assessment_information
    logger.debug(f"Validating UnifiedRiskAssessment: {info.risk_assessment_id if info else 'UNKNOWN'}")

    # 1. Structural Checks on IDs
    if not info:
        raise InvalidRiskAssessmentException("assessment_information is required.")

    if not info.risk_assessment_id or not info.risk_assessment_id.strip():
        raise InvalidRiskAssessmentException("risk_assessment_id cannot be empty or whitespace.")
        
    if not info.incident_id or not info.incident_id.strip():
        raise InvalidRiskAssessmentException("incident_id cannot be empty or whitespace.")
        
    if not info.assessment_id or not info.assessment_id.strip():
        raise InvalidRiskAssessmentException("assessment_id cannot be empty or whitespace.")

    # 2. Context Evaluation Checks
    eval_sec = assessment.context_evaluation
    if not eval_sec:
        raise InvalidRiskAssessmentException("context_evaluation is required.")
    
    if not eval_sec.business_context:
        raise InvalidRiskAssessmentException("business_context is required inside context_evaluation.")
    if not eval_sec.asset_context:
        raise InvalidRiskAssessmentException("asset_context is required inside context_evaluation.")
    if not eval_sec.customer_context:
        raise InvalidRiskAssessmentException("customer_context is required inside context_evaluation.")
    if not eval_sec.transaction_context:
        raise InvalidRiskAssessmentException("transaction_context is required inside context_evaluation.")
    if not eval_sec.data_context:
        raise InvalidRiskAssessmentException("data_context is required inside context_evaluation.")

    # 3. Reference Matching Check
    ref_m5 = assessment.referenced_domain_ai_assessment
    if not ref_m5:
        raise InvalidRiskAssessmentException("referenced_domain_ai_assessment is required.")

    if ref_m5.assessment_id != info.assessment_id:
        raise InvalidRiskAssessmentException(
            f"Mismatched assessment_id reference: info={info.assessment_id}, "
            f"referenced_domain_ai_assessment={ref_m5.assessment_id}"
        )

    if ref_m5.incident_id != info.incident_id:
        raise InvalidRiskAssessmentException(
            f"Mismatched incident_id reference: info={info.incident_id}, "
            f"referenced_domain_ai_assessment={ref_m5.incident_id}"
        )

    # 4. Scores and confidence boundaries
    score_sec = assessment.context_aware_risk_score
    if not score_sec:
        raise InvalidRiskAssessmentException("context_aware_risk_score is required.")

    if score_sec.unified_risk_score < 0.0 or score_sec.unified_risk_score > 100.0:
        raise InvalidRiskAssessmentException(f"Invalid unified_risk_score: {score_sec.unified_risk_score}")

    conf_sec = assessment.confidence_assessment
    if not conf_sec:
        raise InvalidRiskAssessmentException("confidence_assessment is required.")

    if conf_sec.overall_confidence < 0.0 or conf_sec.overall_confidence > 1.0:
        raise InvalidRiskAssessmentException(f"Invalid overall_confidence score: {conf_sec.overall_confidence}")

    logger.info(f"UnifiedRiskAssessment {info.risk_assessment_id} successfully validated.")
