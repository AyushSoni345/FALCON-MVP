from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field, ConfigDict, model_validator

class AssessmentInformation(BaseModel):
    assessment_id: str
    incident_id: str
    incident_category: str
    assessment_timestamp: str
    active_domains: List[str]

class DomainAssessmentDetails(BaseModel):
    domain_score: float = Field(..., ge=0.0, le=100.0)
    confidence: float = Field(..., ge=0.0, le=1.0)
    findings: List[str] = Field(default_factory=list)

class ActiveDomainAssessments(BaseModel):
    behaviour_assessment: Optional[DomainAssessmentDetails] = None
    fraud_assessment: Optional[DomainAssessmentDetails] = None
    cyber_assessment: Optional[DomainAssessmentDetails] = None
    quantum_assessment: Optional[DomainAssessmentDetails] = None

class CrossDomainIntelligence(BaseModel):
    source_domain: str
    target_domain: str
    shared_indicator: str
    impact: str
    correlation_strength: float = Field(default=0.8, ge=0.0, le=1.0)

class CompositeRiskAssessment(BaseModel):
    overall_risk_score: float = Field(..., ge=0.0, le=100.0)
    overall_risk_level: str
    contributing_domains: List[str]
    assessment_confidence: float
    priority: str

class AIEvaluationDetails(BaseModel):
    explanation_summary: str
    key_contributing_factors: List[str] = Field(default_factory=list)
    supporting_evidence: List[str] = Field(default_factory=list)
    conflicting_evidence: List[str] = Field(default_factory=list)

class RecommendedActions(BaseModel):
    recommended_actions: List[str] = Field(default_factory=list)
    recommended_priority: str
    escalation_required: bool
    automation_candidate: bool

class ReferencedCorrelatedSecurityIncident(BaseModel):
    incident_id: str
    incident_timeline: List[str] = Field(default_factory=list)
    attack_graph_reference: str
    hypothesis_reference: str
    confidence_reference: float

class DomainAIAssessment(BaseModel):
    assessment_information: AssessmentInformation = Field(..., alias="Assessment Information")
    active_domain_assessments: ActiveDomainAssessments = Field(..., alias="Active Domain Assessments")
    cross_domain_intelligence: CrossDomainIntelligence = Field(..., alias="Cross-Domain Intelligence")
    composite_risk_assessment: CompositeRiskAssessment = Field(..., alias="Composite Risk Assessment")
    ai_explanation: AIEvaluationDetails = Field(..., alias="AI Explanation")
    recommended_actions: RecommendedActions = Field(..., alias="Recommended Actions")
    referenced_correlated_security_incident: Optional[ReferencedCorrelatedSecurityIncident] = Field(None, alias="Referenced Correlated Security Incident")

    model_config = ConfigDict(populate_by_name=True)

    @model_validator(mode="before")
    @classmethod
    def normalize_module5_output(cls, data: Any) -> Any:
        from typing import Any
        from datetime import datetime
        if not isinstance(data, dict):
            return data

        # 1. Normalize "Assessment Information" / "assessment_information"
        info = data.get("Assessment Information") or data.get("assessment_information")
        if not info or not isinstance(info, dict):
            # Construct it from flat fields at the root
            info = {
                "assessment_id": data.get("assessment_id", "DAA-UNKNOWN"),
                "incident_id": data.get("incident_id", "INC-UNKNOWN"),
                "incident_category": data.get("incident_category", "Cyber"),
                "assessment_timestamp": data.get("assessment_timestamp", datetime.utcnow().isoformat() + "Z"),
                "active_domains": data.get("active_domains", [])
            }
        data["assessment_information"] = info
            
        # 2. Normalize Active Domain Assessments
        active = data.get("Active Domain Assessments") or data.get("active_domain_assessments")
        if active and isinstance(active, dict):
            adapted_active = {}
            for domain in ["behaviour", "fraud", "cyber", "quantum"]:
                d_key = f"{domain}_assessment"
                # Find matching key in raw dict (case insensitive, suffix insensitive)
                raw_key = None
                for k in active.keys():
                    k_lower = k.lower()
                    if k_lower in [domain, f"{domain}_assessment", f"{domain}assessment"]:
                        raw_key = k
                        break
                        
                if raw_key:
                    d_data = active[raw_key]
                    if isinstance(d_data, dict):
                        # Map domain_score
                        score = d_data.get("domain_score")
                        if score is None:
                            score = d_data.get(f"{domain}al_risk_score" if domain == "behaviour" else f"{domain}_risk_score")
                        if score is None:
                            score = 0.0
                            
                        # Map confidence (0-100 to 0-1)
                        conf = d_data.get("confidence", 0.0)
                        if conf > 1.0:
                            conf = conf / 100.0
                        conf = min(1.0, max(0.0, conf))
                        
                        # Map findings
                        findings = d_data.get("findings")
                        if findings is None:
                            findings = []
                            # Extract from anomalies/patterns if behaviour
                            if "behavioural_anomalies" in d_data:
                                for anom in d_data["behavioural_anomalies"]:
                                    if isinstance(anom, dict) and "description" in anom:
                                        findings.append(anom["description"])
                            # Extract from compromised assets / lateral movement if cyber
                            if "detected_attack_pattern" in d_data:
                                findings.append(d_data["detected_attack_pattern"])
                            if "compromised_assets" in d_data:
                                for asset in d_data["compromised_assets"]:
                                    if isinstance(asset, dict) and "compromise_reason" in asset:
                                        findings.append(asset["compromise_reason"])
                                        
                        if not findings:
                            findings = ["Domain assessment indicators observed"]
                            
                        adapted_active[d_key] = {
                            "domain_score": score,
                            "confidence": conf,
                            "findings": findings
                        }
            data["active_domain_assessments"] = adapted_active

        # 3. Normalize Cross-Domain Intelligence
        cross = data.get("Cross-Domain Intelligence") or data.get("cross_domain_intelligence")
        if isinstance(cross, list):
            # Parse source_domain/target_domain from list of strings or active_domains list
            active_list = []
            if info:
                active_list = info.get("active_domains", [])
            source = active_list[0] if active_list else "Behaviour"
            target = active_list[-1] if len(active_list) > 1 else "Fraud"
            
            data["cross_domain_intelligence"] = {
                "source_domain": source,
                "target_domain": target,
                "shared_indicator": "Shared threat signals",
                "impact": "High",
                "correlation_strength": 0.8
            }
        elif cross and isinstance(cross, dict):
            source = cross.get("source_domain")
            if not source:
                domains = cross.get("correlated_domains", [])
                source = domains[0] if domains else "Behaviour"
            target = cross.get("target_domain")
            if not target:
                domains = cross.get("correlated_domains", [])
                target = domains[-1] if len(domains) > 1 else "Fraud"
                
            data["cross_domain_intelligence"] = {
                "source_domain": source,
                "target_domain": target,
                "shared_indicator": cross.get("shared_indicator") or (cross.get("common_indicators", [""])[0] if cross.get("common_indicators") else "Shared Indicators"),
                "impact": cross.get("impact") or "High",
                "correlation_strength": cross.get("correlation_strength", 0.8)
            }

        # 4. Normalize Composite Risk Assessment
        comp = data.get("Composite Risk Assessment") or data.get("composite_risk_assessment")
        if comp and isinstance(comp, dict):
            # Map confidence (0-100 to 0-1)
            raw_conf = comp.get("assessment_confidence", 0.8)
            if raw_conf > 1.0:
                raw_conf = raw_conf / 100.0
            conf = min(1.0, max(0.0, raw_conf))
            
            data["composite_risk_assessment"] = {
                "overall_risk_score": comp.get("overall_risk_score") or comp.get("initial_composite_score", 50.0),
                "overall_risk_level": comp.get("overall_risk_level", "Medium"),
                "contributing_domains": comp.get("contributing_domains", []),
                "assessment_confidence": conf,
                "priority": comp.get("priority", "Medium")
            }

        # 5. Normalize AI Explanation
        exp = data.get("AI Explanation") or data.get("ai_explanation")
        if isinstance(exp, str):
            data["ai_explanation"] = {
                "explanation_summary": exp,
                "key_contributing_factors": [],
                "supporting_evidence": [],
                "conflicting_evidence": []
            }
        elif exp and isinstance(exp, dict):
            data["ai_explanation"] = {
                "explanation_summary": exp.get("explanation_summary", "No summary available"),
                "key_contributing_factors": exp.get("key_contributing_factors") or exp.get("contributing_engines", []),
                "supporting_evidence": exp.get("supporting_evidence", []),
                "conflicting_evidence": exp.get("conflicting_evidence", [])
            }

        # 6. Normalize Recommended Actions
        actions = data.get("Recommended Actions") or data.get("recommended_actions")
        if isinstance(actions, list):
            data["recommended_actions"] = {
                "recommended_actions": actions,
                "recommended_priority": "High",
                "escalation_required": True,
                "automation_candidate": False
            }
        elif actions and isinstance(actions, dict):
            data["recommended_actions"] = actions

        # 7. Normalize Referenced Correlated Security Incident
        inc = data.get("Referenced Correlated Security Incident") or data.get("referenced_correlated_security_incident")
        if isinstance(inc, str):
            data["referenced_correlated_security_incident"] = {
                "incident_id": inc,
                "incident_timeline": [],
                "attack_graph_reference": "G-001",
                "hypothesis_reference": "H-001",
                "confidence_reference": 0.8
            }
        elif inc and isinstance(inc, dict):
            timeline = [str(x) for x in inc.get("incident_timeline") or inc.get("timeline_reference", [])]
            
            graph = inc.get("attack_graph_reference", "G-001")
            if isinstance(graph, list) and graph:
                graph = graph[0]
            elif isinstance(graph, list):
                graph = "G-001"
                
            hyp = inc.get("hypothesis_reference", "H-001")
            if isinstance(hyp, list) and hyp:
                hyp = hyp[0]
            elif isinstance(hyp, list):
                hyp = "H-001"
                
            data["referenced_correlated_security_incident"] = {
                "incident_id": inc.get("incident_id", "SEC-UNKNOWN"),
                "incident_timeline": timeline,
                "attack_graph_reference": str(graph),
                "hypothesis_reference": str(hyp),
                "confidence_reference": inc.get("confidence_reference") or inc.get("confidence_score", 0.8)
            }

        return data
