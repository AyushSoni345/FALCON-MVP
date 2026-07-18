import hashlib
import time
from typing import Dict, Any, Tuple
from datetime import datetime
import uuid

from module6.config.manager import ConfigurationManager
from module6.schemas.domain_ai_assessment import DomainAIAssessment
from module6.schemas.unified_risk_assessment import (
    UnifiedRiskAssessment, AssessmentInformation, RiskSignalAggregation, 
    ContextAwareRiskScore, IncidentClassification, ConfidenceAssessment, 
    PrioritizationDecision, ReferencedDomainAIAssessment
)
from module6.schemas.decision_trace import DecisionTrace
from module6.evaluators import ContextLoader, ContextNormalizer, ContextEvaluator
from module6.engines import (
    RiskScoringPipeline, FalsePositiveSuppressionEngine, ConfidenceFusionEngine, 
    IncidentPrioritizationEngine, ResponsePriorityEngine
)
from module6.repositories.decision_trace_repo import IDecisionTraceRepository
from module6.audit_logging.logger import get_logger
from module6.audit_logging.audit_logger import AuditLogger
from module6.metrics.collector import MetricsCollector
from module6.exceptions.pipeline import PipelineException

logger = get_logger("module6.pipeline")

class EngineExecutionResult:
    def __init__(self, unified_risk_assessment: UnifiedRiskAssessment, decision_trace: DecisionTrace):
        self.unified_risk_assessment = unified_risk_assessment
        self.decision_trace = decision_trace

class Module6Pipeline:
    def __init__(
        self, 
        config_manager: ConfigurationManager,
        trace_repo: IDecisionTraceRepository,
        audit_logger: AuditLogger,
        metrics_collector: MetricsCollector
    ):
        self.config_manager = config_manager
        self.trace_repo = trace_repo
        self.audit_logger = audit_logger
        self.metrics_collector = metrics_collector

        self.context_loader = ContextLoader()
        self.context_normalizer = ContextNormalizer()
        self.context_evaluator = ContextEvaluator()
        
        self.risk_scorer = RiskScoringPipeline(self.config_manager)
        self.suppression_engine = FalsePositiveSuppressionEngine(self.config_manager)
        self.confidence_engine = ConfidenceFusionEngine(self.config_manager)
        self.prioritization_engine = IncidentPrioritizationEngine(self.config_manager)
        self.response_engine = ResponsePriorityEngine()

    def _generate_idempotency_key(self, assessment_id: str, config_ver: str, rule_ver: str) -> str:
        raw = f"{assessment_id}_{config_ver}_{rule_ver}"
        return hashlib.sha256(raw.encode('utf-8')).hexdigest()

    def process(self, assessment: DomainAIAssessment, external_context: Dict[str, Any] = None) -> EngineExecutionResult:
        start_time = time.time()
        try:
            config_ver = self.config_manager.config_version
            rule_ver = self.config_manager.rule_version
            
            # Map dynamic active domains from model to internal dictionary representation
            active_domains_dict = {}
            if assessment.active_domain_assessments.behaviour_assessment:
                active_domains_dict["Behaviour"] = assessment.active_domain_assessments.behaviour_assessment
            if assessment.active_domain_assessments.fraud_assessment:
                active_domains_dict["Fraud"] = assessment.active_domain_assessments.fraud_assessment
            if assessment.active_domain_assessments.cyber_assessment:
                active_domains_dict["Cyber"] = assessment.active_domain_assessments.cyber_assessment
            if assessment.active_domain_assessments.quantum_assessment:
                active_domains_dict["Quantum"] = assessment.active_domain_assessments.quantum_assessment

            idempotency_key = self._generate_idempotency_key(assessment.assessment_information.assessment_id, config_ver, rule_ver)
            
            # Check Idempotency
            cached_trace = self.trace_repo.get_by_idempotency_key(idempotency_key)
            if cached_trace:
                logger.info(f"Idempotency hit for assessment_id={assessment.assessment_information.assessment_id}. TraceID: {cached_trace.trace_id}")
                # We would reconstruct URA from trace in a full implementation, for now we assume if it's cached we just return the trace (or in full prod, store URA too)
                pass # Proceeding for now as we don't cache URA strictly in this demo, but the hook is here.

            # 1 & 2. Load and Normalize Context
            raw_context = self.context_loader.load_context(assessment, external_context)
            normalized_context = self.context_normalizer.normalize(raw_context)

            # 3. Evaluate Context and Completeness
            context_eval, completeness_score = self.context_evaluator.evaluate(normalized_context)

            # 4. Risk Signal Aggregation & Scoring
            weighted_scores, unified_score, scoring_trace = self.risk_scorer.calculate_scores(
                active_domains_dict, context_eval
            )
            
            active_domain_count = len(active_domains_dict)
            corr_strength = assessment.cross_domain_intelligence.correlation_strength

            # 5. False Positive Suppression
            is_suppressed, rule_name, suppression_reason, suppression_trace = self.suppression_engine.evaluate_suppression(
                weighted_scores, context_eval, active_domain_count, corr_strength
            )

            # 6. Confidence Fusion
            avg_ai_conf = sum(d.confidence for d in active_domains_dict.values()) / max(1, active_domain_count)
            overall_conf, conf_trace = self.confidence_engine.calculate_confidence(
                avg_ai_conf, completeness_score, active_domains_dict
            )

            # 7. Incident Prioritization
            priority_level, priority_trace = self.prioritization_engine.evaluate_priority(
                unified_score, context_eval, is_suppressed
            )

            # 8. Response Priority
            response_priority, response_trace = self.response_engine.evaluate_response_priority(priority_level)

            # Construct URA
            ura_id = f"URA-{uuid.uuid4()}"
            current_time = datetime.utcnow().isoformat() + "Z"

            ura = UnifiedRiskAssessment(
                assessment_information=AssessmentInformation(
                    risk_assessment_id=ura_id,
                    incident_id=assessment.assessment_information.incident_id,
                    assessment_id=assessment.assessment_information.assessment_id,
                    assessment_timestamp=current_time,
                    incident_category=assessment.assessment_information.incident_category
                ),
                context_evaluation=context_eval,
                risk_signal_aggregation=RiskSignalAggregation(
                    contributing_domains=list(active_domains_dict.keys()),
                    domain_scores={k: v.domain_score for k, v in active_domains_dict.items()},
                    weighted_scores=weighted_scores,
                    aggregated_score=unified_score
                ),
                context_aware_risk_score=ContextAwareRiskScore(
                    unified_risk_score=unified_score,
                    risk_level="Critical" if unified_score >= 85 else "High" if unified_score >= 70 else "Medium" if unified_score >= 40 else "Low",
                    risk_trend="Stable",
                    scoring_factors=[t["factor"] for t in scoring_trace.get("adjustments_applied", []) if "factor" in t]
                ),
                incident_classification=IncidentClassification(
                    final_incident_type=assessment.assessment_information.incident_category,
                    final_priority=priority_level,
                    business_impact=context_eval.business_context.service_impact,
                    operational_impact="High" if unified_score >= 70 else "Medium",
                    financial_impact="High" if context_eval.transaction_context.transaction_value > 50000 else "Low"
                ),
                confidence_assessment=ConfidenceAssessment(
                    overall_confidence=overall_conf,
                    ai_confidence=avg_ai_conf,
                    business_context_confidence=completeness_score,
                    evidence_strength=conf_trace["components"]["evidence_strength"],
                    false_positive_probability=0.9 if is_suppressed else 0.1
                ),
                prioritization_decision=PrioritizationDecision(
                    priority_level=priority_level,
                    escalation_required=(priority_level in ["P1", "P2"]),
                    false_positive_suppressed=is_suppressed,
                    suppression_reason=suppression_reason,
                    analyst_review_required=(priority_level == "P1")
                ),
                response_priority=response_priority,
                referenced_domain_ai_assessment=ReferencedDomainAIAssessment(
                    assessment_id=assessment.assessment_information.assessment_id,
                    incident_id=assessment.assessment_information.incident_id,
                    active_domain_assessments=assessment.active_domain_assessments,
                    cross_domain_intelligence=assessment.cross_domain_intelligence,
                    composite_risk_assessment=assessment.composite_risk_assessment
                )
            )

            # Construct Trace
            trace_id = f"TRC-{uuid.uuid4()}"
            trace = DecisionTrace(
                trace_id=trace_id,
                idempotency_key=idempotency_key,
                input_assessment_id=assessment.assessment_information.assessment_id,
                incident_id=assessment.assessment_information.incident_id,
                timestamp=current_time,
                config_version=config_ver,
                rule_version=rule_ver,
                active_domain_scores={k: v.domain_score for k, v in active_domains_dict.items()},
                context_values_loaded=normalized_context,
                rule_evaluations=[suppression_trace],
                weight_adjustments_applied=scoring_trace.get("adjustments_applied", []),
                suppression_decisions={"suppressed": is_suppressed, "reason": suppression_reason},
                confidence_fusion_steps=conf_trace,
                final_score_calculation=scoring_trace,
                priority_assignment=priority_trace
            )

            # Persist and Log
            self.trace_repo.save(trace)
            self.audit_logger.log_decision(
                trace_id=trace.trace_id,
                idempotency_key=idempotency_key,
                incident_id=trace.incident_id,
                assessment_id=trace.input_assessment_id,
                metadata={"priority": priority_level, "score": unified_score, "suppressed": is_suppressed}
            )

            # Record Metrics
            latency = (time.time() - start_time) * 1000.0
            self.metrics_collector.record_latency(latency)
            self.metrics_collector.record_processing(priority_level, overall_conf, completeness_score)
            if is_suppressed:
                self.metrics_collector.record_suppression(rule_name or "unknown")

            return EngineExecutionResult(ura, trace)

        except Exception as e:
            self.metrics_collector.record_validation_failure()
            logger.error(f"Pipeline processing failed: {str(e)}")
            raise PipelineException(f"Pipeline execution failed: {str(e)}") from e
