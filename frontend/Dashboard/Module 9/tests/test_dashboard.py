import pytest
from datetime import datetime, UTC
from fastapi.testclient import TestClient

from app.main import app
from app.exceptions.exceptions import IRLPValidationException, DashboardNotFoundException
from app.validators.irlp_validator import validate_irlp
from app.services.dashboard_builder import DashboardBuilder
from app.services.dashboard_manager import DashboardManager
from app.schemas.input import (
    IncidentResponseLearningPackage,
    ResponsePackageInfo,
    IncidentResponsePlan,
    ResponseDecisionTrace,
    ResponseExecutionPlan,
    SOAROrchestrationTask,
    AnalystValidation,
    ContinuousLearningPackage,
    ModelOptimizationRecommendation,
    FeedbackAuditTrail,
    ReferencedThreatReport,
    ExecutiveSummaryReference,
    RootCauseReference,
    EvidenceReference,
    InvestigationReference,
    AnalystSupportReference
)
from app.models.enums import (
    DashboardMode,
    IncidentStatus
)

client = TestClient(app)

# Helper function to generate a valid mock package matching exact Module 8 schema
def get_valid_mock_package() -> IncidentResponseLearningPackage:
    trace = ResponseDecisionTrace(
        decision_factors=["Risk Level: Critical", "Priority: P2"],
        selected_rule="Generalized Cyber Containment Rule"
    )
    
    plan = IncidentResponsePlan(
        incident_type="Cyber",
        response_strategy="Containment",
        recommended_actions=["Isolate host"],
        business_justification="Justification",
        expected_outcome="Outcome",
        response_decision_trace=trace
    )
    
    exec_plan = ResponseExecutionPlan(
        action_sequence=["Isolate host"],
        execution_type="Automated",
        assigned_team="SecOps Incident Response",
        execution_priority="P2",
        estimated_completion_time="4 hours"
    )
    
    task = SOAROrchestrationTask(
        task_id="task_80de4841-536d-51ba-b787-b48656db9332",
        playbook_name="Automated Network Containment Playbook",
        automation_level="Automated",
        prerequisites=[],
        execution_status="Prepared"
    )
    
    report = ReferencedThreatReport(
        report_id="d736e479-c46c-5c30-bd1d-4a9bf359446d",
        executive_summary_reference=ExecutiveSummaryReference(
            unified_risk_score=100.0,
            risk_level="Critical"
        ),
        root_cause_reference=RootCauseReference(
            probable_root_cause="Credential breach"
        ),
        evidence_reference=EvidenceReference(
            evidence_count=5
        ),
        investigation_reference=InvestigationReference(
            priority_artifacts=["logs"]
        ),
        analyst_support_reference=AnalystSupportReference(
            confidence_summary="High confidence"
        )
    )

    return IncidentResponseLearningPackage(
        response_package_info=ResponsePackageInfo(
            response_package_id="pkg_31763d0c-245c-5d81-b0b1-3a1a82997299",
            report_id="d736e479-c46c-5c30-bd1d-4a9bf359446d",
            incident_id="INC-F0AE790D",
            package_timestamp=datetime.now(UTC),
            package_version="1.0",
            package_status="PendingApproval"
        ),
        incident_response_plan=plan,
        response_execution_plan=exec_plan,
        soar_orchestration_tasks=[task],
        analyst_validation=None,
        continuous_learning_package=None,
        model_optimization_recommendations=[],
        feedback_audit_trail=None,
        referenced_threat_report=report
    )

# 1. Validation tests
def test_valid_package_passes():
    pkg = get_valid_mock_package()
    # Should not raise exception
    validate_irlp(pkg)

def test_invalid_package_raises_mismatch_report_id():
    pkg = get_valid_mock_package()
    
    # Cause a mismatch in report ID between response package info and threat report
    info = pkg.response_package_info.model_copy(update={
        "report_id": "d736e479-c46c-5c30-bd1d-4a9bf3599999"
    })
    pkg = pkg.model_copy(update={
        "response_package_info": info
    })
    
    with pytest.raises(IRLPValidationException) as exc:
        validate_irlp(pkg)
    assert "Referential mismatch on report_id" in str(exc.value)

# 2. Builder tests
def test_builder_populates_10_workspaces():
    pkg = get_valid_mock_package()
    dashboard = DashboardBuilder.build_dashboard(pkg, "session-1", DashboardMode.LIVE)
    
    assert dashboard.dashboard_information.dashboard_id == "session-1"
    assert dashboard.live_operations_console.incident_id == "INC-F0AE790D"
    assert dashboard.incident_monitoring_workspace.selected_incident.incident_id == "INC-F0AE790D"
    assert dashboard.explainable_threat_intelligence_workspace.report_id == "d736e479-c46c-5c30-bd1d-4a9bf359446d"
    assert dashboard.response_operations_workspace.containment_status == "Awaiting Containment"
    assert len(dashboard.continuous_learning_workspace.model_optimization_recommendations) == 0
    assert dashboard.referenced_incident_response_learning_package.response_package_id == "pkg_31763d0c-245c-5d81-b0b1-3a1a82997299"

# 3. Manager tests
def test_manager_lifecycle():
    manager = DashboardManager()
    pkg = get_valid_mock_package()
    
    # Load dashboard session
    dashboard = manager.load_dashboard(pkg, mode=DashboardMode.LIVE, refresh_interval=45)
    dash_id = dashboard.dashboard_information.dashboard_id
    
    assert dash_id in manager.active_sessions
    assert manager.get_dashboard(dash_id).dashboard_information.refresh_interval == 45
    
    # Refresh dashboard updates progress
    refreshed = manager.refresh_dashboard(dash_id)
    assert refreshed.incident_monitoring_workspace.response_progress == 0.05
    
    # Add comment
    manager.add_comment(dash_id, "test.user", "This is a comment note.")
    assert len(manager.get_dashboard(dash_id).analyst_interaction_workspace.analyst_comments) == 1
    assert manager.get_dashboard(dash_id).analyst_interaction_workspace.analyst_comments[0].text == "This is a comment note."
    
    # Close workflow action
    new_status = manager.perform_workflow_action(dash_id, "Close", "test.user")
    assert new_status == IncidentStatus.CLOSED
    assert manager.get_dashboard(dash_id).incident_monitoring_workspace.selected_incident.package_status == IncidentStatus.CLOSED.value

# 4. API / HTTP endpoints tests
def test_api_endpoints():
    pkg = get_valid_mock_package()
    payload = pkg.model_dump(mode="json")
    
    # Load POST api
    response = client.post("/api/v1/dashboard/load?mode=Live&refresh_interval=30", json=payload)
    assert response.status_code == 201
    
    db_json = response.json()
    dash_id = db_json["dashboard_information"]["dashboard_id"]
    assert dash_id is not None
    
    # Get GET api
    response = client.get(f"/api/v1/dashboard/{dash_id}")
    assert response.status_code == 200
    assert response.json()["dashboard_information"]["dashboard_id"] == dash_id
    
    # Refresh GET api
    response = client.get(f"/api/v1/dashboard/{dash_id}/refresh")
    assert response.status_code == 200
    
    # Individual Workspace GET api
    response = client.get(f"/api/v1/dashboard/{dash_id}/live")
    assert response.status_code == 200
    assert "incident_id" in response.json()
    
    response = client.get(f"/api/v1/dashboard/{dash_id}/incident-monitoring")
    assert response.status_code == 200
    assert response.json()["selected_incident"]["incident_id"] == "INC-F0AE790D"
    
    response = client.get(f"/api/v1/dashboard/{dash_id}/knowledge-graph")
    assert response.status_code == 200
    
    response = client.get(f"/api/v1/dashboard/{dash_id}/threat-intelligence")
    assert response.status_code == 200
    
    response = client.get(f"/api/v1/dashboard/{dash_id}/response-operations")
    assert response.status_code == 200
    
    response = client.get(f"/api/v1/dashboard/{dash_id}/continuous-learning")
    assert response.status_code == 200
    
    response = client.get(f"/api/v1/dashboard/{dash_id}/executive-analytics")
    assert response.status_code == 200
    
    response = client.get(f"/api/v1/dashboard/{dash_id}/analyst-workspace")
    assert response.status_code == 200
    
    response = client.get(f"/api/v1/dashboard/{dash_id}/references")
    assert response.status_code == 200
    
    # Comment POST api
    response = client.post(f"/api/v1/dashboard/{dash_id}/comments?author=test.analyst&text=hello")
    assert response.status_code == 201
    
    # Tag POST api
    response = client.post(f"/api/v1/dashboard/{dash_id}/tags?tag=HNW_CUSTOMER")
    assert response.status_code == 200
    assert "HNW_CUSTOMER" in response.json()["tags"]

    # Workflow action POST api
    response = client.post(f"/api/v1/dashboard/{dash_id}/workflow?action=Close&actor=test.analyst")
    assert response.status_code == 200
    assert response.json()["status"] == IncidentStatus.CLOSED.value
    
    # Negative test: invalid session ID
    response = client.get("/api/v1/dashboard/invalid-session-uuid-999")
    assert response.status_code == 404
