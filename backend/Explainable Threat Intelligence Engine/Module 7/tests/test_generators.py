from app.templates.manager import ReportTemplateManager
from app.formatters.formatter import ReportFormatter
from app.generators.executive_summary import ExecutiveSummaryGenerator
from app.generators.incident_narrative import IncidentNarrativeBuilder
from app.generators.root_cause import RootCauseAnalysisEngine
from app.generators.evidence_trace import EvidenceTraceEngine
from app.generators.ai_reasoning import ExplainableAIReasoningEngine
from app.generators.timeline import HumanReadableTimelineGenerator
from app.generators.investigation_guidance import InvestigationGuidanceEngine
from app.generators.decision_support import AnalystDecisionSupportGenerator
from app.models.enums import RiskLevel

def test_executive_summary_generator(mock_assessment):
    templates = ReportTemplateManager()
    formatter = ReportFormatter()
    gen = ExecutiveSummaryGenerator(templates, formatter)
    
    res = gen.generate(mock_assessment)
    assert res.unified_risk_score == 85.5
    assert res.risk_level == RiskLevel.HIGH
    assert res.recommended_priority == "P1"
    assert res.primary_cause == "Credential Exposure (Anomalous Session Credentials)"
    assert "URA-20260715-0001" not in res.incident_overview
    assert "Account Takeover" in res.incident_overview

def test_incident_narrative_builder(mock_assessment):
    templates = ReportTemplateManager()
    formatter = ReportFormatter()
    gen = IncidentNarrativeBuilder(templates, formatter)
    
    res = gen.generate(mock_assessment)
    assert "Account Takeover" in res.narrative_summary
    assert len(res.attack_progression) > 0
    assert any("USR-MOCK" in entity for entity in res.affected_entities)
    assert any("Retail Transfers" in consequence for consequence in res.business_consequences)

def test_root_cause_analysis_engine(mock_assessment):
    templates = ReportTemplateManager()
    formatter = ReportFormatter()
    gen = RootCauseAnalysisEngine(templates, formatter)
    
    res = gen.generate(mock_assessment)
    assert "Compromised consumer credentials" in res.probable_root_cause
    assert len(res.contributing_factors) == 4
    assert any("High Net Worth Customer" in factor for factor in res.contributing_factors)
    assert "Failed authentication attempt" in res.triggering_event
    assert res.confidence == 0.85

def test_evidence_trace_engine(mock_assessment_with_fraud):
    templates = ReportTemplateManager()
    formatter = ReportFormatter()
    gen = EvidenceTraceEngine(templates, formatter)
    
    res = gen.generate(mock_assessment_with_fraud)
    assert len(res.evidence_sequence) == 5
    assert any("active domains: behaviour, fraud" in seq.lower() for seq in res.evidence_sequence)
    # Check that Referenced Domain AI assessment results are captured
    assert any("active domains: Behaviour, Fraud" in ai for ai in res.ai_assessments)
    assert any("Reference ID: DAA-20260715-0001" in ai for ai in res.ai_assessments)

def test_explainable_ai_reasoning_engine(mock_assessment):
    templates = ReportTemplateManager()
    formatter = ReportFormatter()
    gen = ExplainableAIReasoningEngine(templates, formatter)
    
    res = gen.generate(mock_assessment)
    assert any("active domains: Behaviour" in step for step in res.reasoning_steps)
    assert any("Risk evaluation trend flagged as: 'Stable'" in factor for factor in res.supporting_factors)
    assert any("false positive probability estimated at 0.15" in factor.lower() for factor in res.contradictory_factors)
    assert "assessment concluded with" in res.ai_decision_summary

def test_human_readable_timeline_generator(mock_assessment):
    templates = ReportTemplateManager()
    formatter = ReportFormatter()
    gen = HumanReadableTimelineGenerator(templates, formatter)
    
    res = gen.generate(mock_assessment)
    assert len(res.entries) == 3
    assert "Step 1: Incident detected" in res.entries[0].description
    assert "Step 2: Risk assessment performed" in res.entries[1].description
    assert "Step 3: Final business-aware risk established" in res.entries[2].description

def test_investigation_guidance_engine(mock_assessment):
    templates = ReportTemplateManager()
    formatter = ReportFormatter()
    gen = InvestigationGuidanceEngine(templates, formatter)
    
    res = gen.generate(mock_assessment)
    assert any("Review transaction authorization logs" in step for step in res.recommended_investigation_steps)
    assert any("Backup Archive Asymmetric Keys" in artifact for artifact in res.priority_artifacts)
    assert any("customer segment 'High Net Worth'" in query for query in res.additional_queries)

def test_analyst_decision_support_generator(mock_assessment):
    templates = ReportTemplateManager()
    formatter = ReportFormatter()
    gen = AnalystDecisionSupportGenerator(templates, formatter)
    
    res = gen.generate(mock_assessment)
    assert "overall confidence of 0.85" in res.confidence_summary
    assert "Escalation is recommended" in res.escalation_recommendation
    assert "eligible for automated" in res.automation_recommendation.lower()
    assert "High Net Worth Customer: True" in res.analyst_notes
