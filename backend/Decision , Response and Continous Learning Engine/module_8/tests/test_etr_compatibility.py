import pytest
from datetime import datetime
from module_8.main import process_threat_report, apply_analyst_decision

@pytest.fixture
def real_m7_etr_payload():
    return {
        "report_information": {
            "report_id": "91d609b7-f4c9-5bb9-9d5b-e5627f331908",
            "risk_assessment_id": "URA-f5cd13e0-3aa9-4d0e-a5a8-7c0a7b3038e8",
            "incident_id": "INC-C50EE929",
            "report_timestamp": "2026-07-16T04:57:42.328452Z",
            "report_version": "1.0.0",
            "report_status": "Final"
        },
        "executive_summary": {
            "incident_overview": "A Critical-severity security event classified as 'Cyber' was identified implicating the primary entity 'Unknown Entity'. Driven by Credential Exposure (False), the activity resulted in a context-aware risk score of 100.0. Given the potential business impact on 'Core Banking' (Medium), this incident has been assigned a priority rating of 'P2' for immediate SOC triage.",
            "unified_risk_score": 100.0,
            "risk_level": "Critical",
            "primary_cause": "Credential Exposure (False)",
            "business_impact": "Medium",
            "recommended_priority": "P2"
        },
        "incident_narrative": {
            "narrative_summary": "A security event classified as 'Cyber' was identified involving the primary entity 'Unknown Entity'. The anomalous sequence was initiated at 2026-07-15 14:10:22 UTC and persisted over a duration of 10.00 seconds, implicating 1 critical corporate or customer asset(s).",
            "attack_progression": [
                "The incident began when activity associated with entity 'Unknown Entity' was initiated via payment channel 'Unknown'. Subsequently, the multi-domain analytics engine activated evaluations for the active domains: Behaviour -> Cyber -> Fraud. The activity later progressed to destination asset 'True', ultimately resulting in a security escalation at 2026-07-15 14:10:22 UTC.",
                "The evaluation of the associated data context indicates 'PII' classification, with potential cryptographic access exposure related to 'False'."
            ],
            "affected_entities": [
                "Primary implicated account: Unknown Entity.",
                "Impacted production system: True (Asset Type: Unknown).",
                "Customer segment: VIP (Risk Profile: Medium)."
            ],
            "business_consequences": [
                "Business Process: Core Banking (Criticality Level: Medium).",
                "Service Impact: Medium.",
                "Operational Impact: High.",
                "Financial Impact: High (Financial Exposure: 82500.0)."
            ]
        },
        "root_cause_analysis": {
            "probable_root_cause": "Based on the analytical facts provided in the risk assessment, the probable root cause of the incident is identified as 'Compromised consumer credentials causing unauthorized high-value transfers.', initially triggered by 'Anomalous Unknown session authorization matching credential risk profile (False).'. This led to a Critical risk level designation under the following contributing factors: Confidential data exposure profile (PII), Customer risk profile rated as 'Medium', High Net Worth Customer (HNWI) target account profile, Target production system criticality rated as 'Critical'. The resulting operational impact is established as: High.",
            "contributing_factors": [
                "Confidential data exposure profile (PII).",
                "Customer risk profile rated as 'Medium'.",
                "High Net Worth Customer (HNWI) target account profile.",
                "Target production system criticality rated as 'Critical'."
            ],
            "triggering_event": "Anomalous Unknown session authorization matching credential risk profile (False).",
            "impact_summary": "High",
            "confidence": 0.85
        },
        "evidence_chain": {
            "evidence_sequence": [
                "1. Risk Signals: Multi-domain assessment analyzed active domains: Behaviour, Cyber, Fraud with an aggregated score of 100.0.",
                "2. Business Context: Process 'Core Banking' evaluated with high-net-worth status: True.",
                "3. Confidence: Overall evaluation confidence calculated at 0.85 (False Positive Probability: 0.10).",
                "4. Final Decision: Incident prioritized as level 'P2' with escalation status set to True.",
                "5. References: Traced to domain AI assessment reference identifier 'DAA-20260715-0001'."
            ],
            "supporting_events": [
                "Domain 'Behaviour' risk score: 62.0 (Weight contributor: 31.0).",
                "Domain 'Cyber' risk score: 100.0 (Weight contributor: 50.0).",
                "Domain 'Fraud' risk score: 0.0 (Weight contributor: 0.0).",
                "Credential exposure risk assessment: False.",
                "PII exposure risk level: False."
            ],
            "graph_paths": [
                "Data store reference node: False.",
                "Relational Graph Traversal Path: Entity 'Unknown Entity' -> Payment Channel 'Unknown' -> System Host 'True'"
            ],
            "ai_assessments": [
                "AI explanation summary: Multi-domain AI assessment confirmed threat activity across active domains: Behaviour, Cyber, Fraud.",
                "Assessment Reference ID: DAA-20260715-0001.",
                "Overall AI evaluation confidence score: 0.81."
            ],
            "business_context": [
                "Business Process: Core Banking (Criticality Level: Medium).",
                "Overall financial process exposure: 82500.0.",
                "Service Impact: Medium."
            ]
        },
        "explainable_ai_reasoning": {
            "reasoning_steps": [
                "Evaluated telemetry risk scores across active domains: Behaviour, Cyber, Fraud.",
                "Calibrated the base aggregated score of 100.0 to 100.0 based on context metrics.",
                "Assessed final classification confidence and false positive probabilities."
            ],
            "supporting_factors": [
                "Evidence strength evaluated at 0.85.",
                "Risk evaluation trend flagged as: 'Stable'.",
                "Strong multi-domain correlation of behavioral and fraud signals."
            ],
            "contradictory_factors": [
                "Business context confidence offset rating of 0.80.",
                "False positive probability estimated at 0.10."
            ],
            "ai_decision_summary": "The multi-domain AI assessment concluded with the classification of 'Multi-domain AI assessment confirmed threat activity across active domains: Behaviour, Cyber, Fraud.' at an overall evaluation confidence of 0.85. The decision path was primarily influenced by Evaluated telemetry risk scores across active domains: Behaviour, Cyber, Fraud.; Calibrated the base aggregated score of 100.0 to 100.0 based on context metrics.; Assessed final classification confidence and false positive probabilities.. System confidence was strengthened by Evidence strength evaluated at 0.85., Risk evaluation trend flagged as: 'Stable'., Strong multi-domain correlation of behavioral and fraud signals., while it was counterbalanced by Business context confidence offset rating of 0.80., False positive probability estimated at 0.10.."
        },
        "human_readable_timeline": {
            "entries": [
                {
                    "timestamp": "2026-07-15T14:10:22.251077Z",
                    "description": "Step 1: Incident detected was executed by entity 'Unknown Entity' with an extraction confidence of 0.81.",
                    "significance": "Event represents a key milestone (Incident detected) in the threat progression timeline."
                },
                {
                    "timestamp": "2026-07-15T14:10:27.251077Z",
                    "description": "Step 2: Risk assessment performed was executed by entity 'DomainEngines(Behaviour, Cyber, Fraud)' with an extraction confidence of 0.85.",
                    "significance": "Event represents a key milestone (Risk assessment performed) in the threat progression timeline."
                },
                {
                    "timestamp": "2026-07-15T14:10:32.251077Z",
                    "description": "Step 3: Final business-aware risk established was executed by entity 'Module_6_Risk_Engine' with an extraction confidence of 0.85.",
                    "significance": "Incident score aggregated to 100.0 (Level: Critical)."
                }
            ]
        },
        "investigation_guidance": {
            "recommended_investigation_steps": [
                "Conduct secure customer verification check using procedures defined for segment 'VIP'.",
                "Correlate customer risk profile 'Medium' with historical transaction frequencies for segment 'VIP'.",
                "Inspect host authorization telemetry for production system 'True' to identify potentially compromised sessions.",
                "Review transaction authorization logs for payment channel 'Unknown' during the identified incident window.",
                "Verify credential exposure records matching type 'False' against recent login attempts."
            ],
            "priority_artifacts": [
                "Cryptographic key authorization histories for asset 'False'.",
                "System access and session events for production host 'True'.",
                "Transaction logs and transmission payloads on payment channel 'Unknown'."
            ],
            "additional_queries": [
                "Query historical session durations for customer segment 'VIP'.",
                "Retrieve active login sessions matching credential exposure classification 'False'."
            ],
            "related_entities": [
                "Cryptographic Key Archive: False.",
                "Customer Risk Segment: VIP.",
                "Production Endpoint Host: True."
            ],
            "recommended_validation": [
                "Conduct secure customer verification check using procedures defined for segment 'VIP'.",
                "Initiate multi-factor identity challenge sequence for the primary account owner."
            ]
        },
        "analyst_decision_support": {
            "confidence_summary": "The overall confidence of 0.85 is supported by strong evidence strength (0.85) and a low false positive probability (0.10).",
            "escalation_recommendation": "Escalation is recommended based on priority level 'P2' and analyst review requirements.",
            "automation_recommendation": "Based on security orchestration policies, this incident is eligible for automated response playbooks.",
            "analyst_notes": "Analyst review is 'required'. Customer Risk Profile is 'Medium' and Vulnerable Customer Status is False. High Net Worth Customer: True."
        },
        "referenced_unified_risk_assessment": {
            "risk_assessment_id": "URA-f5cd13e0-3aa9-4d0e-a5a8-7c0a7b3038e8",
            "incident_classification": {
                "final_incident_type": "Malware",
                "final_priority": "P2",
                "business_impact": "Medium",
                "operational_impact": "High",
                "financial_impact": "High"
            },
            "context_aware_risk_score": {
                "unified_risk_score": 100.0,
                "risk_level": "Critical",
                "risk_trend": "Stable",
                "scoring_factors": ["ImpossibleTravel"]
            },
            "confidence_assessment": {
                "overall_confidence": 0.85,
                "ai_confidence": 0.81,
                "business_context_confidence": 0.80,
                "evidence_strength": 0.85,
                "false_positive_probability": 0.10
            },
            "prioritization_decision": {
                "priority_level": "P2",
                "escalation_required": True,
                "false_positive_suppressed": False,
                "suppression_reason": None,
                "analyst_review_required": True
            },
            "response_priority": {
                "recommended_response_level": "Immediate",
                "response_sla": "30m",
                "response_urgency": "High",
                "automation_eligible": True
            }
        }
    }

def test_real_m7_etr_parsing_and_processing(real_m7_etr_payload):
    # 1. Verify parsing and processing succeeds natively (no schema validation errors)
    package = process_threat_report(real_m7_etr_payload)
    
    # 2. Verify decision package generation
    assert package.response_package_info.report_id == "91d609b7-f4c9-5bb9-9d5b-e5627f331908"
    assert package.response_package_info.package_status == "PendingApproval"
    assert package.incident_response_plan.incident_type == "Malware"
    
    # 3. Verify SOAR task generation (tasks are Prepared, sequentially linked)
    assert len(package.soar_orchestration_tasks) > 0
    for task in package.soar_orchestration_tasks:
        assert task.execution_status == "Prepared"
        assert task.playbook_name == "Standard Malware Response"
        
    # 4. Verify Analyst feedback decision flow
    updated_package = apply_analyst_decision(
        package=package,
        etr_payload=real_m7_etr_payload,
        analyst_id="analyst_1",
        decision="Approved",
        verdict="True Positive",
        notes="Confirmed cyber malware alert."
    )
    
    assert updated_package.analyst_validation.analyst_decision == "Approved"
    assert updated_package.response_package_info.package_status == "Approved"
    assert updated_package.soar_orchestration_tasks[0].execution_status == "Ready"
    
    # 5. Verify Continuous Learning Package generation
    assert updated_package.continuous_learning_package is not None
    assert updated_package.continuous_learning_package.analyst_verdict == "True Positive"
    assert updated_package.continuous_learning_package.learning_label == "positive"
    
    # 6. Verify optimization vectors are empty for True Positive (no false positive retrain needed)
    assert len(updated_package.model_optimization_recommendations) == 0

def test_real_m7_etr_determinism(real_m7_etr_payload):
    package_1 = process_threat_report(real_m7_etr_payload)
    package_2 = process_threat_report(real_m7_etr_payload)
    
    # Verify deterministic output IDs
    id1 = package_1.response_package_info.response_package_id
    id2 = package_2.response_package_info.response_package_id
    ts1 = package_1.response_package_info.package_timestamp
    ts2 = package_2.response_package_info.package_timestamp
    
    assert id1 == id2
    assert ts1 == ts2
    
    # Verify deterministic SOAR tasks
    tasks1 = [t.task_id for t in package_1.soar_orchestration_tasks]
    tasks2 = [t.task_id for t in package_2.soar_orchestration_tasks]
    assert tasks1 == tasks2

def test_real_m7_etr_false_positive_optimization(real_m7_etr_payload):
    package = process_threat_report(real_m7_etr_payload)
    
    # Analyst rejects as False Positive
    updated_package = apply_analyst_decision(
        package=package,
        etr_payload=real_m7_etr_payload,
        analyst_id="analyst_2",
        decision="Rejected",
        verdict="False Positive",
        notes="False alert in Module 6 risk calibration weights."
    )
    
    # Verify optimization recommendation generated
    assert len(updated_package.model_optimization_recommendations) == 1
    rec = updated_package.model_optimization_recommendations[0]
    assert rec.retraining_candidate is True
    assert "Module 6 Risk Calibration" in rec.suspected_affected_modules
