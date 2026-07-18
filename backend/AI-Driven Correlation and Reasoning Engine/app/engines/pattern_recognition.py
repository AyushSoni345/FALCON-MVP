from typing import Any, Dict, List
from module4.app.models.models import SecurityGraphEvent
from module4.app.engines.interfaces import BasePatternRecognitionEngine

class PatternRecognitionEngine(BasePatternRecognitionEngine):
    """
    Evaluates chronological sequences and graph structure to detect
    known multi-stage attack and fraud patterns.
    """

    def recognize(
        self,
        events: List[SecurityGraphEvent],
        temporal_output: Dict[str, Any],
        graph_output: Dict[str, Any]
    ) -> Dict[str, Any]:
        detected_patterns = []
        observations = []
        pattern_confidence = 0.5

        # Extract relationships and node types
        relationships = graph_output.get("relationships", [])
        nodes = graph_output.get("nodes", [])
        shared_entities = graph_output.get("shared_entities", {})

        node_types = [n.node_type for n in nodes]
        rel_types = [r.relationship_type for r in relationships]

        event_types_lower = [e.event_context.event_type.lower() for e in events]
        event_categories_lower = [e.event_context.event_category.lower() for e in events]
        source_systems_lower = [e.event_context.source_system.lower() for e in events]

        has_login = "LOGGED_IN_FROM" in rel_types or any("login" in et for et in event_types_lower)
        has_beneficiary = any("beneficiary" in et for et in event_types_lower)
        has_new_device = "Device" in node_types or "Endpoint" in node_types or any("device" in n.node_id.lower() for n in nodes)
        has_malware = "Malware" in node_types or "IOC" in node_types or "INFECTED_BY" in rel_types or any("malware" in n.node_id.lower() for n in nodes)
        has_transfer = any("transfer" in et or "transaction" in et or "payment" in et for et in event_types_lower)
        has_exfil = any("exfil" in et or "dlp" in et or "outbound" in et for et in event_types_lower) or any("dlp" in ss for ss in source_systems_lower)
        has_employee = "Employee" in node_types or any("employee" in n.node_id.lower() for n in nodes)
        has_escalation = any("escalation" in et or "privilege" in et for et in event_types_lower)

        # 1. Malware Infection
        if has_malware:
            detected_patterns.append("Malware Infection")
            observations.append("Malware Infection: Confirmed linkage to malware signatures or indicators of compromise (IOCs).")
            pattern_confidence += 0.2

        # 2. Credential Theft
        if has_login and (has_new_device or "VPN" in node_types or any("vpn" in ss for ss in source_systems_lower)):
            detected_patterns.append("Credential Theft")
            observations.append("Credential Theft: Authentication session established from an uncharacteristic IP/VPN gateway.")
            pattern_confidence += 0.15

        # 3. Account Takeover
        if has_login and has_beneficiary:
            detected_patterns.append("Account Takeover")
            observations.append("Account Takeover: Session verification followed by high-risk beneficiary profile updates.")
            pattern_confidence += 0.2

        # 4. Financial Fraud
        if (has_beneficiary or has_login) and has_transfer:
            detected_patterns.append("Financial Fraud")
            observations.append("Financial Fraud: Outbound transaction request registered near session initialization or beneficiary change.")
            pattern_confidence += 0.2

        # 5. Insider Threat
        if has_employee and (has_escalation or any("unauthorized" in et for et in event_types_lower)):
            detected_patterns.append("Insider Threat")
            observations.append("Insider Threat: Privilege escalation or resource access attempted by internal employee identity.")
            pattern_confidence += 0.2

        # 6. Data Exfiltration
        if has_exfil or (has_transfer and "Server" in node_types):
            detected_patterns.append("Data Exfiltration")
            observations.append("Data Exfiltration: High-volume outbound telemetry transfer or external data access detected.")
            pattern_confidence += 0.15

        # 7. Hybrid Incident
        # Defined as combination of Cyber AND Financial threats
        cyber_patterns = {"Malware Infection", "Credential Theft", "Insider Threat", "Data Exfiltration"}
        financial_patterns = {"Financial Fraud", "Account Takeover"}
        has_cyber = any(p in cyber_patterns for p in detected_patterns)
        has_financial = any(p in financial_patterns for p in detected_patterns)
        if has_cyber and has_financial:
            detected_patterns.append("Hybrid Incident")
            observations.append("Hybrid Incident: Multi-domain cyber vector correlated directly with transactional bank fraud.")
            pattern_confidence += 0.1

        # Base case if no patterns detected
        if not detected_patterns:
            detected_patterns.append("Unknown Threat Pattern")
            observations.append("No known signatures or predefined attack chains matched exactly.")
            pattern_confidence = 0.3

        return {
            "detected_patterns": list(set(detected_patterns)),
            "observations": observations,
            "pattern_confidence": min(1.0, pattern_confidence)
        }
