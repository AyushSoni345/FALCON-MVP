# OpenAPI Swagger selectables for FALCON Module 9

SWAGGER_EXAMPLES = {
    "Financial Fraud": {
        "summary": "Financial Fraud Example",
        "description": "High-value transfer matching anomalous IMPS session coordinates.",
        "value": {
            "response_package_info": {
                "response_package_id": "pkg_31763d0c-245c-5d81-b0b1-3a1a82997299",
                "report_id": "d736e479-c46c-5c30-bd1d-4a9bf359446d",
                "incident_id": "INC-F0AE790D",
                "package_timestamp": "2026-07-16T07:45:01.469635Z",
                "package_version": "1.0",
                "package_status": "PendingApproval"
            },
            "incident_response_plan": {
                "incident_type": "Fraud",
                "response_strategy": "Containment",
                "recommended_actions": [
                    "Isolate user session tokens on IMPS portal",
                    "Block fraudulent beneficiary transfer target account",
                    "Trigger out-of-band transaction authorization check"
                ],
                "business_justification": "Automatically contain high-risk fraud threats to prevent unauthorized ledger movements.",
                "expected_outcome": "High-value transfer prevented before clearing transaction cycle.",
                "response_decision_trace": {
                    "decision_factors": [
                        "Risk Level: Critical",
                        "Priority: P2",
                        "Root Cause: Compromised customer credentials causing unauthorized IMPS transfer attempt.",
                        "Confidence: 90.92%"
                    ],
                    "selected_rule": "Generalized Fraud Containment Rule"
                }
            },
            "response_execution_plan": {
                "action_sequence": [
                    "Isolate user session tokens on IMPS portal",
                    "Block fraudulent beneficiary transfer target account",
                    "Trigger out-of-band transaction authorization check"
                ],
                "execution_type": "Automated",
                "assigned_team": "Fraud Operations",
                "execution_priority": "P2",
                "estimated_completion_time": "2 hours"
            },
            "soar_orchestration_tasks": [
                {
                    "task_id": "task_80de4841-536d-51ba-b787-b48656db9332",
                    "playbook_name": "Automated Transaction Freeze Playbook",
                    "automation_level": "Automated",
                    "prerequisites": [],
                    "execution_status": "Prepared"
                },
                {
                    "task_id": "task_22b8249d-620b-5f7e-a3f6-58f0374d300d",
                    "playbook_name": "Automated Token Revocation Playbook",
                    "automation_level": "Automated",
                    "prerequisites": ["task_80de4841-536d-51ba-b787-b48656db9332"],
                    "execution_status": "Prepared"
                }
            ],
            "analyst_validation": None,
            "continuous_learning_package": None,
            "model_optimization_recommendations": [],
            "feedback_audit_trail": None,
            "referenced_threat_report": {
                "report_id": "d736e479-c46c-5c30-bd1d-4a9bf359446d",
                "executive_summary_reference": {
                    "unified_risk_score": 100.0,
                    "risk_level": "Critical"
                },
                "root_cause_reference": {
                    "probable_root_cause": "Based on the analytical facts provided in the risk assessment, the probable root cause of the incident is identified as 'Compromised consumer credentials causing unauthorized high-value transfers.', initially triggered by 'Anomalous IMPS session authorization matching credential risk profile (False).'. This led to a Critical risk level designation under the following contributing factors: Confidential data exposure profile (Public), Customer risk profile rated as 'High', High Net Worth Customer (HNWI) target account profile, Target production system criticality rated as 'Critical'."
                },
                "evidence_reference": {
                    "evidence_count": 5
                },
                "investigation_reference": {
                    "priority_artifacts": [
                        "Transaction logs and transmission payloads on payment channel 'IMPS'.",
                        "System access and session events for production host 'True'."
                    ]
                },
                "analyst_support_reference": {
                    "confidence_summary": "The overall confidence of 0.91 is supported by strong evidence strength (1.00) and a low false positive probability (0.10)."
                }
            }
        }
    },
    "Cyber Attack": {
        "summary": "Cyber Attack Example",
        "description": "Network breach with malicious Command & Control communication.",
        "value": {
            "response_package_info": {
                "response_package_id": "pkg_31763d0c-245c-5d81-b0b1-3a1a82997299",
                "report_id": "d736e479-c46c-5c30-bd1d-4a9bf359446d",
                "incident_id": "INC-F0AE790D",
                "package_timestamp": "2026-07-16T07:45:01.469635Z",
                "package_version": "1.0",
                "package_status": "PendingApproval"
            },
            "incident_response_plan": {
                "incident_type": "Cyber",
                "response_strategy": "Containment",
                "recommended_actions": [
                    "Isolate target hosts and network subnets",
                    "Block malicious command and control source IPs",
                    "Revoke active system authentication tokens"
                ],
                "business_justification": "Automatically contain high-risk cyber threats to prevent data leakage and system compromise.",
                "expected_outcome": "Target entities contained, preventing threat propagation.",
                "response_decision_trace": {
                    "decision_factors": [
                        "Risk Level: Critical",
                        "Priority: P2",
                        "Root Cause: Based on the analytical facts provided in the risk assessment, the probable root cause of the incident is identified as 'Compromised consumer credentials causing unauthorized high-value transfers.', initially triggered by 'Anomalous IMPS session authorization matching credential risk profile (False).'. This led to a Critical risk level designation under the following contributing factors: Confidential data exposure profile (Public), Customer risk profile rated as 'High', High Net Worth Customer (HNWI) target account profile, Target production system criticality rated as 'Critical'. The resulting operational impact is established as: High.",
                        "Confidence: 90.92%"
                    ],
                    "selected_rule": "Generalized Cyber Containment Rule"
                }
            },
            "response_execution_plan": {
                "action_sequence": [
                    "Isolate target hosts and network subnets",
                    "Block malicious command and control source IPs",
                    "Revoke active system authentication tokens"
                ],
                "execution_type": "Automated",
                "assigned_team": "SecOps Incident Response",
                "execution_priority": "P2",
                "estimated_completion_time": "4 hours"
            },
            "soar_orchestration_tasks": [
                {
                    "task_id": "task_80de4841-536d-51ba-b787-b48656db9332",
                    "playbook_name": "Automated Network Containment Playbook",
                    "automation_level": "Automated",
                    "prerequisites": [],
                    "execution_status": "Prepared"
                },
                {
                    "task_id": "task_22b8249d-620b-5f7e-a3f6-58f0374d300d",
                    "playbook_name": "Automated Network Containment Playbook",
                    "automation_level": "Automated",
                    "prerequisites": [
                        "task_80de4841-536d-51ba-b787-b48656db9332"
                    ],
                    "execution_status": "Prepared"
                },
                {
                    "task_id": "task_2ab7f274-5dc3-5166-aa84-2c0947fe55eb",
                    "playbook_name": "Automated Network Containment Playbook",
                    "automation_level": "Automated",
                    "prerequisites": [
                        "task_22b8249d-620b-5f7e-a3f6-58f0374d300d"
                    ],
                    "execution_status": "Prepared"
                }
            ],
            "analyst_validation": None,
            "continuous_learning_package": None,
            "model_optimization_recommendations": [],
            "feedback_audit_trail": None,
            "referenced_threat_report": {
                "report_id": "d736e479-c46c-5c30-bd1d-4a9bf359446d",
                "executive_summary_reference": {
                    "unified_risk_score": 100.0,
                    "risk_level": "Critical"
                },
                "root_cause_reference": {
                    "probable_root_cause": "Based on the analytical facts provided in the risk assessment, the probable root cause of the incident is identified as 'Compromised consumer credentials causing unauthorized high-value transfers.', initially triggered by 'Anomalous IMPS session authorization matching credential risk profile (False).'. This led to a Critical risk level designation under the following contributing factors: Confidential data exposure profile (Public), Customer risk profile rated as 'High', High Net Worth Customer (HNWI) target account profile, Target production system criticality rated as 'Critical'. The resulting operational impact is established as: High."
                },
                "evidence_reference": {
                    "evidence_count": 5
                },
                "investigation_reference": {
                    "priority_artifacts": [
                        "Transaction logs and transmission payloads on payment channel 'IMPS'.",
                        "System access and session events for production host 'True'.",
                        "Cryptographic key authorization histories for asset 'False'."
                    ]
                },
                "analyst_support_reference": {
                    "confidence_summary": "The overall confidence of 0.91 is supported by strong evidence strength (1.00) and a low false positive probability (0.10)."
                }
            }
        }
    },
    "False Positive": {
        "summary": "False Positive Example",
        "description": "Legitimate transaction with low anomaly deviation score.",
        "value": {
            "response_package_info": {
                "response_package_id": "pkg_44253d0c-245c-5d81-b0b1-3a1a82997299",
                "report_id": "e936e479-c46c-5c30-bd1d-4a9bf359446d",
                "incident_id": "INC-FP-091",
                "package_timestamp": "2026-07-16T08:00:00.000000Z",
                "package_version": "1.0",
                "package_status": "Closed"
            },
            "incident_response_plan": {
                "incident_type": "Fraud",
                "response_strategy": "Alert Verification",
                "recommended_actions": [
                    "Perform location check against user travel itinerary",
                    "Suppress active block timers"
                ],
                "business_justification": "Low anomaly trigger match under standard user flight window.",
                "expected_outcome": "System false positive flagged, no isolation actions taken.",
                "response_decision_trace": {
                    "decision_factors": [
                        "Risk Level: Low",
                        "Priority: P3",
                        "Root Cause: Regular transaction match",
                        "Confidence: 35.5%"
                    ],
                    "selected_rule": "Standard Verification suppression rule"
                }
            },
            "response_execution_plan": {
                "action_sequence": [
                    "Perform location check against user travel itinerary"
                ],
                "execution_type": "Automated",
                "assigned_team": "Fraud Operations",
                "execution_priority": "P3",
                "estimated_completion_time": "15 minutes"
            },
            "soar_orchestration_tasks": [
                {
                    "task_id": "task_99de4841-536d-51ba-b787-b48656db9332",
                    "playbook_name": "Automated Location Query Playbook",
                    "automation_level": "Automated",
                    "prerequisites": [],
                    "execution_status": "Completed"
                }
            ],
            "analyst_validation": {
                "analyst_decision": "Rejected",
                "validation_notes": "Flight confirms user was traveling. Legitimate access.",
                "override_reason": "Matched travel logs",
                "approval_timestamp": "2026-07-16T08:05:00Z"
            },
            "continuous_learning_package": {
                "analyst_verdict": "False Positive",
                "learning_label": "Regular Traveler",
                "contributing_patterns": ["Frequent Flyer Path"],
                "contextual_features": {},
                "learning_priority": "Low"
            },
            "model_optimization_recommendations": [],
            "feedback_audit_trail": [
                {
                    "feedback_id": "aud-fp-1",
                    "analyst_id": "sonia.soc",
                    "decision_history": ["Dismissed"],
                    "feedback_timestamp": "2026-07-16T08:05:00Z",
                    "audit_status": "Approved"
                }
            ],
            "referenced_threat_report": {
                "report_id": "e936e479-c46c-5c30-bd1d-4a9bf359446d",
                "executive_summary_reference": {
                    "unified_risk_score": 25.0,
                    "risk_level": "Low"
                },
                "root_cause_reference": {
                    "probable_root_cause": "Legitimate transaction activity matched to client profile."
                },
                "evidence_reference": {
                    "evidence_count": 1
                },
                "investigation_reference": {
                    "priority_artifacts": [
                        "Travel itinerary confirmation details"
                    ]
                },
                "analyst_support_reference": {
                    "confidence_summary": "Confidence level matches baseline threshold limits."
                }
            }
        }
    }
}
