import logging
from typing import Any, Dict, List, Optional
from module5.models.input.incident import CorrelatedSecurityIncident, GraphNode
from module5.models.output.assessment import CompromisedAsset, LateralMovement, MalwarePresence, CyberAssessment

logger = logging.getLogger("FALCON.Module5.Cyber.Components")

class CyberContextExtractor:
    """
    Extracts infrastructure, network, Host, and Active Directory logs from the CorrelatedSecurityIncident.
    """
    def extract(self, incident: CorrelatedSecurityIncident) -> Dict[str, Any]:
        context = {
            "compromised_node_ids": [],
            "malware_evidence": incident.correlated_evidence.malware_matches or [],
            "ioc_matches": incident.correlated_evidence.IOC_matches or [],
            "lateral_movements": incident.attack_graph.lateral_movements or [],
            "servers": incident.incident_context.affected_servers or [],
            "applications": incident.incident_context.affected_applications or [],
            "devices": incident.incident_context.affected_devices or [],
            "employees": incident.incident_context.affected_employees or []
        }
        
        # Identify nodes representing assets
        for node in incident.attack_graph.attack_nodes:
            if node.node_type.upper() in ["DEVICE", "SERVER", "ENDPOINT", "HOST", "DATABASE", "GATEWAY"]:
                context["compromised_node_ids"].append(node.node_id)
                
        return context


class AttackIndicatorDetector:
    """
    Analyzes specific indicators of compromise (IOCs) and alerts.
    """
    def detect_indicators(self, context: Dict[str, Any], incident: CorrelatedSecurityIncident) -> List[str]:
        indicators = []
        if context["malware_evidence"]:
            indicators.extend([f"Malware detected: {m}" for m in context["malware_evidence"]])
        if context["ioc_matches"]:
            indicators.extend([f"IOC Match: {ioc}" for ioc in context["ioc_matches"]])
        
        # Parse reasoning patterns
        for pattern in incident.ai_reasoning.supporting_patterns:
            indicators.append(f"Reasoning pattern: {pattern}")
            
        return indicators


class AttackPatternDetector:
    """
    Groups individual indicators into higher-level attack patterns.
    """
    def detect_patterns(self, indicators: List[str], incident: CorrelatedSecurityIncident) -> str:
        # Generate primary attack pattern string
        patterns = []
        summary = incident.ai_reasoning.anomaly_summary.lower()
        
        # Identify sequence based on support patterns or summary
        for pat in incident.ai_reasoning.supporting_patterns:
            patterns.append(pat)

        if not patterns:
            if "lateral" in summary:
                patterns.append("Lateral Movement")
            if "malware" in summary or "ransomware" in summary:
                patterns.append("Malware Infection")
            if "credential" in summary or "brute-force" in summary:
                patterns.append("Credential Theft")
            if "privilege" in summary:
                patterns.append("Privilege Escalation")

        if patterns:
            # Construct chain (e.g. Credential Theft -> Lateral Movement)
            return " → ".join(patterns)
        return "Unknown Exploitation Chain"


class AttackStageClassifier:
    """
    Classifies the incident into a primary MITRE ATT&CK stage.
    """
    def classify_stage(self, pattern: str, incident: CorrelatedSecurityIncident) -> str:
        pattern_lower = pattern.lower()
        summary = incident.ai_reasoning.anomaly_summary.lower()

        if "exfiltration" in summary or "exfiltrate" in summary:
            return "Exfiltration"
        if "lateral" in pattern_lower or "lateral" in summary:
            return "Lateral Movement"
        if "privilege" in pattern_lower or "escalate" in summary:
            return "Privilege Escalation"
        if "credential" in pattern_lower or "dumping" in summary:
            return "Credential Access"
        if "malware" in pattern_lower or "execution" in summary:
            return "Execution"
        if "persistence" in summary:
            return "Persistence"
        if "defense evasion" in summary:
            return "Defense Evasion"
        
        # Default to credential access if unspecified and we see compromised logins
        return "Credential Access"


class CompromisedAssetAnalyzer:
    """
    Identifies and evaluates compromised infrastructure assets.
    """
    def analyze_assets(self, context: Dict[str, Any], incident: CorrelatedSecurityIncident) -> List[CompromisedAsset]:
        compromised = []
        node_map = {node.node_id: node for node in incident.attack_graph.attack_nodes}

        for node_id in context["compromised_node_ids"]:
            node = node_map.get(node_id)
            if not node:
                continue
            
            # Estimate risk parameters based on properties
            props = node.properties
            severity = props.get("severity", "MEDIUM")
            reason = props.get("compromise_reason") or f"Active involvement in attack path {node.node_id}."
            
            compromised.append(CompromisedAsset(
                asset_id=node.node_id,
                asset_type=node.node_type,
                asset_name=props.get("name") or props.get("hostname") or node.node_id,
                compromise_reason=reason,
                severity=severity,
                confidence=85.0,
                graph_reference=[node.node_id]
            ))

        # Fallback if no node_ids mapped but context shows servers/devices
        if not compromised:
            for srv in context["servers"]:
                compromised.append(CompromisedAsset(
                    asset_id=srv,
                    asset_type="Server",
                    asset_name=srv,
                    compromise_reason="Host associated with exfiltration or lateral movements.",
                    severity="HIGH",
                    confidence=80.0,
                    graph_reference=[]
                ))
            for dev in context["devices"]:
                compromised.append(CompromisedAsset(
                    asset_id=dev,
                    asset_type="Device",
                    asset_name=dev,
                    compromise_reason="Client device initiating compromised session.",
                    severity="MEDIUM",
                    confidence=80.0,
                    graph_reference=[]
                ))
                
        return compromised


class LateralMovementAnalyzer:
    """
    Tracks and formats lateral movement paths.
    """
    def analyze_movement(self, context: Dict[str, Any], incident: CorrelatedSecurityIncident) -> Optional[LateralMovement]:
        if not context["lateral_movements"] and not any("lateral" in p.lower() for p in incident.ai_reasoning.supporting_patterns):
            return None

        # Build movement path (mock from attack paths or text)
        path = []
        for path_obj in incident.attack_graph.attack_paths:
            path.extend(path_obj.path_nodes)
            
        if not path:
            path = context["compromised_node_ids"]
            
        affected = [a for a in context["servers"]] + [d for d in context["devices"]]
        
        return LateralMovement(
            detected=True,
            confidence=90.0,
            movement_path=path,
            affected_assets=list(set(affected)),
            supporting_evidence=context["lateral_movements"] or ["Lateral movement detected via graph path correlation."]
        )


class MalwareAnalyzer:
    """
    Evaluates malware presence and IOC matches.
    """
    def analyze_malware(self, context: Dict[str, Any], incident: CorrelatedSecurityIncident) -> Optional[MalwarePresence]:
        if not context["malware_evidence"] and not any("malware" in p.lower() for p in incident.ai_reasoning.supporting_patterns):
            return None

        family = context["malware_evidence"][0] if context["malware_evidence"] else "GenericMalware"
        m_type = "Trojan"
        if "ransomware" in incident.ai_reasoning.anomaly_summary.lower():
            m_type = "Ransomware"
        elif "credential" in incident.ai_reasoning.anomaly_summary.lower():
            m_type = "Credential Stealer"

        return MalwarePresence(
            detected=True,
            malware_family=family,
            malware_type=m_type,
            ioc_matches=context["ioc_matches"],
            confidence=95.0,
            supporting_evidence=context["malware_evidence"]
        )


class CyberRiskCalculator:
    """
    Calculates the cyber risk sub-score and confidence.
    """
    def calculate(self, compromised: List[CompromisedAsset], lateral: Optional[LateralMovement], malware: Optional[MalwarePresence], incident_confidence: float) -> tuple[float, float]:
        if not compromised and not lateral and not malware:
            return 0.0, 0.0

        # Heuristic scoring based on assets & lateral movements
        risk_score = 30.0
        
        # High value if lateral movement exists
        if lateral:
            risk_score += 35.0
        if malware:
            risk_score += 25.0
            
        # Assets severity booster
        max_severity = 0.0
        severity_map = {"LOW": 10, "MEDIUM": 30, "HIGH": 50, "CRITICAL": 65}
        for asset in compromised:
            val = severity_map.get(asset.severity.upper(), 30)
            if val > max_severity:
                max_severity = val
                
        risk_score += max_severity
        risk_score = min(risk_score, 100.0)

        # Confidence assessment
        base_confidence = 85.0
        if compromised:
            base_confidence = sum(c.confidence for c in compromised) / len(compromised)
            
        confidence = (base_confidence * 0.6) + (incident_confidence * 100 * 0.4)
        confidence = min(max(confidence, 0.0), 100.0)

        return round(risk_score, 2), round(confidence, 2)


class CyberSignalGenerator:
    """
    Generates cyber threat signals for other engines.
    """
    def generate_signals(self, pattern: str, stage: str, lateral: Optional[LateralMovement], malware: Optional[MalwarePresence]) -> List[str]:
        signals = []
        if "Credential" in pattern:
            signals.append("Credential Compromise Detected")
        if lateral:
            signals.append("Lateral Movement Detected")
        if malware:
            signals.append("Malware Detected")
        if stage in ["Exfiltration", "Command and Control"]:
            signals.append("C2/Data Exfiltration Risk")
        
        return signals


class CyberRecommendationGenerator:
    """
    Suggests advisory actions for infrastructure mitigation.
    """
    def generate_recommendations(self, compromised: List[CompromisedAsset], lateral: Optional[LateralMovement], malware: Optional[MalwarePresence]) -> List[str]:
        recommendations = []
        
        if compromised:
            for asset in compromised:
                recommendations.append(f"Isolate compromised asset {asset.asset_name} from network.")
        if lateral:
            recommendations.append("Audit session logs traversing Active Directory and block suspicious lateral routes.")
        if malware:
            recommendations.append(f"Deploy anti-malware cleanup policy and scan endpoints for {malware.malware_family}.")

        recommendations.append("Reset active authentication credentials for affected employees.")
        return list(set(recommendations))


class CyberAssessmentBuilder:
    """
    Assembles final CyberAssessment output model.
    """
    def build(self, pattern: str, stage: str, compromised: List[CompromisedAsset], lateral: Optional[LateralMovement], malware: Optional[MalwarePresence], risk_score: float, confidence: float, evidence: List[str]) -> CyberAssessment:
        return CyberAssessment(
            detected_attack_pattern=pattern,
            attack_stage=stage,
            compromised_assets=compromised,
            lateral_movement=lateral,
            malware_presence=malware,
            cyber_risk_score=risk_score,
            confidence=confidence,
            supporting_evidence=evidence
        )
