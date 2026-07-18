import math
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set
from module5.models.input.incident import CorrelatedSecurityIncident, TimelineStep, GraphNode
from module5.models.output.assessment import BehaviouralAnomaly, BehaviourAssessment
from module5.config.settings import settings

logger = logging.getLogger("FALCON.Module5.Behaviour.Components")

class BehaviourContextExtractor:
    """
    Extracts behavioral context (devices, sessions, IPs, geographic and temporal events)
    from the CorrelatedSecurityIncident.
    """
    def extract(self, incident: CorrelatedSecurityIncident) -> Dict[str, Any]:
        context = {
            "entity": incident.incident_information.primary_entity,
            "devices": incident.incident_context.affected_devices or [],
            "sessions": [],
            "ips": [],
            "logins": [],
            "locations": [],
            "failed_auths": 0,
            "timestamps": []
        }

        # Gather sessions, ips and geolocations from attack graph nodes
        ip_locations = {}
        for node in incident.attack_graph.attack_nodes:
            node_type_upper = node.node_type.upper()
            if node_type_upper == "IP":
                context["ips"].append(node.node_id)
                props = node.properties
                geo = props.get("geolocation") or props.get("location") or props.get("country")
                if geo:
                    ip_locations[node.node_id] = geo
                    context["locations"].append(geo)
            elif node_type_upper == "SESSION":
                context["sessions"].append(node.node_id)
            elif node_type_upper == "DEVICE":
                if node.node_id not in context["devices"]:
                    context["devices"].append(node.node_id)

        # Parse timeline steps for behavioral events
        for step in incident.incident_timeline:
            action = step.action.upper()
            context["timestamps"].append(step.timestamp)
            if "LOGIN" in action or "AUTH" in action:
                context["logins"].append({
                    "timestamp": step.timestamp,
                    "action": step.action,
                    "entity": step.entity,
                    "confidence": step.confidence
                })
            if "FAILED" in action or "FAILURE" in action:
                context["failed_auths"] += 1

        # Fallback geo extraction from nodes if empty
        if not context["locations"]:
            for node in incident.attack_graph.attack_nodes:
                if "location" in node.properties:
                    context["locations"].append(node.properties["location"])
                elif "country" in node.properties:
                    context["locations"].append(node.properties["country"])

        # Deduplicate
        context["locations"] = list(set(context["locations"]))
        return context


class BehaviourProfileProvider:
    """
    Infers a baseline profile representing normal/expected behavior.
    Can be replaced in the future by ML/GNN historical profile loaders.
    """
    def get_profile(self, incident: CorrelatedSecurityIncident, context: Dict[str, Any]) -> Dict[str, Any]:
        # Basic inferred profile (in real life, this would hit database for historical profiles)
        return {
            "primary_entity": context["entity"],
            "known_devices": ["DEV-TRUSTED-01"], # Mock known trusted device
            "known_ips": ["192.168.10.1"],
            "expected_locations": ["IN", "India"], # Mock normal location
            "expected_hours": list(range(9, 21)), # 9 AM to 9 PM
            "max_failed_auth_threshold": 3
        }


class BehaviourComparator:
    """
    Compares the current context against the profile baseline.
    """
    def compare(self, context: Dict[str, Any], profile: Dict[str, Any]) -> Dict[str, Any]:
        deviations = {
            "unknown_device": False,
            "unknown_location": False,
            "impossible_travel": False,
            "abnormal_hours": False,
            "excessive_auth_failures": False
        }

        # Check for unknown device (devices not in known_devices list)
        for dev in context["devices"]:
            if dev not in profile["known_devices"]:
                deviations["unknown_device"] = True

        # Check abnormal hours
        for ts in context["timestamps"]:
            if ts.hour not in profile["expected_hours"]:
                deviations["abnormal_hours"] = True

        # Check auth failures
        if context["failed_auths"] > profile["max_failed_auth_threshold"]:
            deviations["excessive_auth_failures"] = True

        # Impossible travel calculation (heuristics)
        # If we have multiple locations or abnormal locations
        for loc in context["locations"]:
            if loc not in profile["expected_locations"]:
                deviations["unknown_location"] = True
                # Simple heuristic: if we have multiple locations in short time
                if len(context["locations"]) > 1:
                    deviations["impossible_travel"] = True

        return deviations


class BehaviourAnomalyDetector:
    """
    Identifies specific behavioral anomalies from the incident context and comparator results.
    """
    def detect(self, incident: CorrelatedSecurityIncident, context: Dict[str, Any], deviations: Dict[str, Any]) -> List[BehaviouralAnomaly]:
        anomalies = []
        event_uuids = [step.event_uuid for step in incident.incident_timeline]
        node_ids = [node.node_id for node in incident.attack_graph.attack_nodes]

        # 1. Impossible Travel
        if deviations["impossible_travel"] or "impossible travel" in [a.lower() for a in incident.correlated_evidence.behavioral_anomalies]:
            anomalies.append(BehaviouralAnomaly(
                anomaly_id="ANOM-BEH-001",
                anomaly_type="Impossible Travel",
                severity="HIGH",
                description=f"Multiple logins detected from geographically disparate locations in a time frame impossible to traverse.",
                supporting_events=event_uuids[:2],
                supporting_graph_nodes=[n for n in node_ids if "IP" in n or "Device" in n][:2],
                confidence=95.0
            ))

        # 2. Unknown Device Login
        if deviations["unknown_device"] or "new device" in [a.lower() for a in incident.correlated_evidence.behavioral_anomalies]:
            anomalies.append(BehaviouralAnomaly(
                anomaly_id="ANOM-BEH-002",
                anomaly_type="New Device",
                severity="MEDIUM",
                description=f"Login sequence initiated from an uncharacteristic, newly registered device profile.",
                supporting_events=event_uuids[:1],
                supporting_graph_nodes=[n for n in node_ids if "Device" in n][:1],
                confidence=85.0
            ))

        # 3. Abnormal Hours
        if deviations["abnormal_hours"]:
            anomalies.append(BehaviouralAnomaly(
                anomaly_id="ANOM-BEH-003",
                anomaly_type="Unusual Login Time",
                severity="LOW",
                description="Session or transactions initiated during atypical working hours of the user profile.",
                supporting_events=event_uuids[:1],
                supporting_graph_nodes=[],
                confidence=70.0
            ))

        # 4. Concurrent Sessions
        if "concurrent sessions" in [a.lower() for a in incident.correlated_evidence.behavioral_anomalies] or len(context["sessions"]) > 1:
            anomalies.append(BehaviouralAnomaly(
                anomaly_id="ANOM-BEH-004",
                anomaly_type="Concurrent Sessions",
                severity="HIGH",
                description="Active concurrent sessions from differing network nodes using identical credentials.",
                supporting_events=event_uuids,
                supporting_graph_nodes=node_ids[:2],
                confidence=90.0
            ))

        # 5. Excessive Authentication Failure
        if deviations["excessive_auth_failures"]:
            anomalies.append(BehaviouralAnomaly(
                anomaly_id="ANOM-BEH-005",
                anomaly_type="High Authentication Failure Rate",
                severity="MEDIUM",
                description="A burst of failed authentication attempts preceding a successful session.",
                supporting_events=event_uuids,
                supporting_graph_nodes=[],
                confidence=88.0
            ))

        # General fallbacks from original Module 4 behavioral anomalies
        for i, original_anom in enumerate(incident.correlated_evidence.behavioral_anomalies):
            # Avoid duplicating
            exists = any(a.anomaly_type.lower() == original_anom.lower() for a in anomalies)
            if not exists:
                anomalies.append(BehaviouralAnomaly(
                    anomaly_id=f"ANOM-BEH-M4-{i}",
                    anomaly_type=original_anom,
                    severity="MEDIUM",
                    description=f"Behavioral anomaly identified by graph correlation: {original_anom}.",
                    supporting_events=event_uuids,
                    supporting_graph_nodes=node_ids[:1],
                    confidence=80.0
                ))

        return anomalies


class BehaviourPatternDetector:
    """
    Groups individual anomalies and deviations into macro behavioural patterns.
    """
    def detect_patterns(self, anomalies: List[BehaviouralAnomaly]) -> List[str]:
        patterns = []
        types = {a.anomaly_type for a in anomalies}

        # Rules for pattern extraction
        if "Impossible Travel" in types or "Concurrent Sessions" in types:
            patterns.append("Credential Misuse")
        if "New Device" in types or "Unusual Login Time" in types:
            patterns.append("Behaviour Drift")
        if "Concurrent Sessions" in types:
            patterns.append("Session Abuse")
        if len(types) >= 3:
            patterns.append("Identity Inconsistency")
            patterns.append("Progressive behavioural escalation")
        
        # Deduplicate
        return list(set(patterns))


class BehaviourRiskCalculator:
    """
    Calculates the engine's sub-score risk (0-100) and confidence (0-100).
    """
    def calculate(self, anomalies: List[BehaviouralAnomaly], patterns: List[str], incident_confidence: float) -> tuple[float, float]:
        if not anomalies:
            return 0.0, 0.0

        # Base score on anomalies count and severity
        risk_map = {"LOW": 20, "MEDIUM": 50, "HIGH": 80, "CRITICAL": 95}
        total_risk = 0.0
        max_risk = 0.0
        
        for anom in anomalies:
            val = risk_map.get(anom.severity.upper(), 50)
            total_risk += val
            if val > max_risk:
                max_risk = val

        # Calculate average and combine with max risk
        avg_risk = total_risk / len(anomalies)
        # Final risk is a weighted combo (70% max risk, 30% average risk) plus minor pattern multiplier
        risk_score = min((max_risk * 0.7) + (avg_risk * 0.3) + (len(patterns) * 2), 100.0)

        # Confidence: average confidence of anomalies weighted by the incident confidence from Module 4
        anoms_confidence = sum(a.confidence for a in anomalies) / len(anomalies)
        # Weighted confidence: 60% engine-confidence, 40% incident-confidence
        confidence = (anoms_confidence * 0.6) + (incident_confidence * 100 * 0.4)
        confidence = min(max(confidence, 0.0), 100.0)

        return round(risk_score, 2), round(confidence, 2)


class BehaviourSignalGenerator:
    """
    Generates behavior-specific signal strings for cross-domain sharing.
    """
    def generate_signals(self, anomalies: List[BehaviouralAnomaly], patterns: List[str]) -> List[str]:
        signals = []
        types = {a.anomaly_type for a in anomalies}
        
        if "Impossible Travel" in types:
            signals.append("Impossible Travel Detected")
        if "New Device" in types:
            signals.append("Credential Misuse (New Device)")
        if "Concurrent Sessions" in types:
            signals.append("Concurrent Session Activity")
        if "Credential Misuse" in patterns:
            signals.append("Credential Misuse Detected")
        if "Behaviour Drift" in patterns:
            signals.append("Behavioural Drift Observed")

        return signals


class BehaviourRecommendationGenerator:
    """
    Suggests next-step advisory actions for security analysts.
    """
    def generate_recommendations(self, anomalies: List[BehaviouralAnomaly], patterns: List[str]) -> List[str]:
        recommendations = []
        types = {a.anomaly_type for a in anomalies}

        if "Impossible Travel" in types or "Concurrent Sessions" in types:
            recommendations.append("Require out-of-band Step-Up MFA immediately.")
            recommendations.append("Force session termination and credential reset.")
        if "New Device" in types:
            recommendations.append("Validate device fingerprint and verify registered user profile.")
        if "High Authentication Failure Rate" in types:
            recommendations.append("Investigate account auth logs for distributed brute-force signs.")
        
        # Base recommendations
        recommendations.append("Initiate active user monitoring in Identity logs.")
        return list(set(recommendations))


class BehaviourAssessmentBuilder:
    """
    Constructs the final BehaviourAssessment output model structure.
    """
    def build(self, anomalies: List[BehaviouralAnomaly], patterns: List[str], risk_score: float, confidence: float, evidence: List[str]) -> BehaviourAssessment:
        return BehaviourAssessment(
            behavioural_anomalies=anomalies,
            behavioural_patterns=patterns,
            behavioural_risk_score=risk_score,
            confidence=confidence,
            supporting_evidence=evidence
        )
