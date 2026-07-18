from typing import Dict, Any, Optional
from datetime import datetime
from module_8.models.input_models import ExplainableThreatReport
from module_8.models.output_models import (
    IncidentResponseLearningPackage, 
    ResponsePackageInfo, 
    FeedbackAuditTrail, 
    ReferencedExplainableThreatReport
)
from module_8.engines.response_strategy_engine import ResponseStrategyEngine
from module_8.engines.playbook_engine import PlaybookEngine
from module_8.engines.soar_task_generator import SOARTaskGenerator
from module_8.engines.analyst_feedback_engine import AnalystFeedbackEngine
from module_8.engines.learning_generator import LearningGenerator
from module_8.engines.optimization_engine import OptimizationEngine
from module_8.services.validation_service import ValidationService
from module_8.utils.helpers import generate_id, current_timestamp
from module_8.utils.logger import get_logger

logger = get_logger(__name__)

class ResponseService:
    def __init__(self):
        self.validation_service = ValidationService()
        self.strategy_engine = ResponseStrategyEngine()
        self.playbook_engine = PlaybookEngine()
        self.soar_generator = SOARTaskGenerator()
        self.feedback_engine = AnalystFeedbackEngine()
        self.learning_generator = LearningGenerator()
        self.optimization_engine = OptimizationEngine()

    def process_incident(self, etr_payload: Dict[str, Any]) -> IncidentResponseLearningPackage:
        logger.info("Processing new incoming ETR payload.")
        
        # 1. Validate Input
        etr = self.validation_service.validate_etr(etr_payload)
        
        # 2. Evaluate Strategy
        matched_rule = self.strategy_engine.evaluate_strategy(etr)
        
        # 3. Generate Plans
        response_plan, execution_plan = self.playbook_engine.generate_plans(etr, matched_rule)
        
        # 4. Generate SOAR Tasks (Prepared for execution)
        soar_tasks = self.soar_generator.generate_tasks(matched_rule, status="Prepared", seed=etr.report_information.report_id)
        
        try:
            etr_dt = datetime.fromisoformat(etr.report_information.report_timestamp.replace("Z", "+00:00"))
        except Exception:
            etr_dt = current_timestamp()
            
        # Construct Initial Package Info
        package_info = ResponsePackageInfo(
            response_package_id=generate_id("pkg", etr.report_information.report_id),
            report_id=etr.report_information.report_id,
            incident_id=etr.report_information.incident_id,
            package_timestamp=etr_dt,
            package_version="1.0",
            package_status="PendingApproval"
        )
        
        referenced_report = ReferencedExplainableThreatReport(
            report_id=etr.report_information.report_id,
            executive_summary_reference={"unified_risk_score": etr.executive_summary.unified_risk_score, "risk_level": etr.executive_summary.risk_level},
            root_cause_reference={"probable_root_cause": etr.root_cause_analysis.probable_root_cause},
            evidence_reference={"evidence_count": len(etr.evidence_chain.evidence_sequence)},
            investigation_reference={"priority_artifacts": etr.investigation_guidance.priority_artifacts},
            analyst_support_reference={"confidence_summary": etr.analyst_decision_support.confidence_summary}
        )
        
        return IncidentResponseLearningPackage(
            response_package_info=package_info,
            incident_response_plan=response_plan,
            response_execution_plan=execution_plan,
            soar_orchestration_tasks=soar_tasks,
            referenced_threat_report=referenced_report
        )

    def apply_analyst_feedback(self, package: IncidentResponseLearningPackage, etr: ExplainableThreatReport, analyst_id: str, decision: str, verdict: str, notes: str) -> IncidentResponseLearningPackage:
        logger.info(f"Applying analyst feedback. Decision: {decision}, Verdict: {verdict}")
        
        try:
            etr_dt = datetime.fromisoformat(etr.report_information.report_timestamp.replace("Z", "+00:00"))
        except Exception:
            etr_dt = package.response_package_info.package_timestamp
            
        # 1. Validation Logic
        validation = self.feedback_engine.process_feedback(decision=decision, notes=notes, timestamp=etr_dt)
        package.analyst_validation = validation
        
        # 2. Update status and tasks based on decision
        if decision == "Rejected":
            package.response_package_info.package_status = "Rejected"
            for task in package.soar_orchestration_tasks:
                task.execution_status = "Blocked"
        elif decision == "Approved":
            package.response_package_info.package_status = "Approved"
            for task in package.soar_orchestration_tasks:
                task.execution_status = "Ready" # Ready for Module 9 to execute
        elif decision == "Modified":
            package.response_package_info.package_status = "Modified"
            for task in package.soar_orchestration_tasks:
                task.execution_status = "Ready"
                
        # 3. Learning & Optimization logic based on verdict
        if package.response_package_info.package_status in ["Approved", "Modified", "Rejected"]:
            # Generate Learning Package
            learning_pkg = self.learning_generator.generate_learning_package(verdict=verdict, etr=etr)
            package.continuous_learning_package = learning_pkg
            
            # Generate Optimizations
            optimizations = self.optimization_engine.generate_recommendations(verdict=verdict, notes=notes)
            package.model_optimization_recommendations = optimizations
            
        # 4. Append to Audit Trail
        audit_event = {
            "action": "Feedback Applied",
            "decision": decision,
            "verdict": verdict,
            "timestamp": etr_dt.isoformat()
        }
        
        if package.feedback_audit_trail:
            package.feedback_audit_trail.decision_history.append(audit_event)
            package.feedback_audit_trail.feedback_timestamp = etr_dt
        else:
            package.feedback_audit_trail = FeedbackAuditTrail(
                feedback_id=generate_id("audit", package.response_package_info.response_package_id),
                analyst_id=analyst_id,
                decision_history=[audit_event],
                feedback_timestamp=etr_dt,
                audit_status="Verified"
            )
            
        return package
