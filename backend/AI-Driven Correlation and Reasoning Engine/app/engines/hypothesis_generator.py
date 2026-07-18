import uuid
from typing import Any, Dict, List
from module4.app.models.models import SecurityGraphEvent, ThreatHypothesis
from module4.app.engines.interfaces import BaseHypothesisGenerator

class HypothesisGenerator(BaseHypothesisGenerator):
    """
    Generates and ranks multiple competing hypotheses based on the gathered evidence.
    """

    def generate_hypotheses(
        self,
        events: List[SecurityGraphEvent],
        evidence_output: Dict[str, Any]
    ) -> List[ThreatHypothesis]:
        hypotheses: List[ThreatHypothesis] = []

        IOC_matches = evidence_output.get("IOC_matches", [])
        malware_matches = evidence_output.get("malware_matches", [])
        fraud_matches = evidence_output.get("fraud_matches", [])
        behavioral_anomalies = evidence_output.get("behavioral_anomalies", [])
        contradictory = evidence_output.get("contradictory_evidence", [])

        event_types_lower = [e.event_context.event_type.lower() for e in events]
        source_systems_lower = [e.event_context.source_system.lower() for e in events]
        nodes = []
        for e in events:
            nodes.extend(e.graph_nodes)
        node_types = [n.node_type for n in nodes]
        node_ids = [n.node_id.lower() for n in nodes]

        has_login = any("login" in et for et in event_types_lower)
        has_beneficiary = any("beneficiary" in et for et in event_types_lower)
        has_device = "Device" in node_types or "Endpoint" in node_types or any("device" in nid for nid in node_ids)
        has_malware = "Malware" in node_types or "IOC" in node_types or any("malware" in nid for nid in node_ids)
        has_transfer = any("transfer" in et or "transaction" in et or "payment" in et for et in event_types_lower)
        has_exfil = any("exfil" in et or "dlp" in et or "outbound" in et for et in event_types_lower) or any("dlp" in ss for ss in source_systems_lower)
        has_employee = "Employee" in node_types or any("employee" in nid for nid in node_ids)
        has_escalation = any("escalation" in et or "privilege" in et for et in event_types_lower)
        has_email = any("email" in et or "mail" in et for et in event_types_lower) or any("email" in ss for ss in source_systems_lower)

        # Base likelihoods
        evidence_ids = IOC_matches + malware_matches + fraud_matches + behavioral_anomalies

        # 1. Credential Theft
        ct_like = 0.1
        if has_login:
            ct_like += 0.4
            if has_device or any("vpn" in ss for ss in source_systems_lower):
                ct_like += 0.25
        hypotheses.append(ThreatHypothesis(
            hypothesis_id=f"HYP-CT-{uuid.uuid4().hex[:4].upper()}",
            hypothesis_type="Credential Theft",
            description="Compromised credentials used to authenticate from an external endpoint.",
            supporting_evidence=evidence_ids,
            contradictory_evidence=contradictory,
            likelihood=round(max(0.05, min(0.95, ct_like - 0.1 * len(contradictory))), 2)
        ))

        # 2. Account Takeover
        ato_like = 0.1
        if has_login and has_beneficiary:
            ato_like += 0.7
        elif has_login and has_transfer:
            ato_like += 0.4
        hypotheses.append(ThreatHypothesis(
            hypothesis_id=f"HYP-ATO-{uuid.uuid4().hex[:4].upper()}",
            hypothesis_type="Account Takeover",
            description="Unidentified third party taking control of customer session for transactional manipulation.",
            supporting_evidence=evidence_ids,
            contradictory_evidence=contradictory,
            likelihood=round(max(0.05, min(0.95, ato_like - 0.1 * len(contradictory))), 2)
        ))

        # 3. Financial Fraud
        ff_like = 0.1
        if has_transfer:
            ff_like += 0.5
            if has_beneficiary or fraud_matches:
                ff_like += 0.25
        hypotheses.append(ThreatHypothesis(
            hypothesis_id=f"HYP-FF-{uuid.uuid4().hex[:4].upper()}",
            hypothesis_type="Financial Fraud",
            description="Unauthorized financial transfer initiated following credential access or routing change.",
            supporting_evidence=evidence_ids,
            contradictory_evidence=contradictory,
            likelihood=round(max(0.05, min(0.95, ff_like - 0.1 * len(contradictory))), 2)
        ))

        # 4. Insider Threat
        it_like = 0.1
        if has_employee:
            it_like += 0.3
            if has_escalation or has_exfil:
                it_like += 0.35
        hypotheses.append(ThreatHypothesis(
            hypothesis_id=f"HYP-IT-{uuid.uuid4().hex[:4].upper()}",
            hypothesis_type="Insider Threat",
            description="Internal actor abusing authorized permissions to extract data or elevate privilege.",
            supporting_evidence=evidence_ids,
            contradictory_evidence=contradictory,
            likelihood=round(max(0.05, min(0.95, it_like - 0.1 * len(contradictory))), 2)
        ))

        # 5. Malware Infection
        mi_like = 0.1
        if has_malware:
            mi_like += 0.7
        hypotheses.append(ThreatHypothesis(
            hypothesis_id=f"HYP-MI-{uuid.uuid4().hex[:4].upper()}",
            hypothesis_type="Malware Infection",
            description="Active execution of malicious software targeting infrastructure or devices.",
            supporting_evidence=evidence_ids,
            contradictory_evidence=contradictory,
            likelihood=round(max(0.05, min(0.95, mi_like - 0.1 * len(contradictory))), 2)
        ))

        # 6. Business Email Compromise
        bec_like = 0.1
        if has_email and (has_transfer or has_login):
            bec_like += 0.6
        hypotheses.append(ThreatHypothesis(
            hypothesis_id=f"HYP-BEC-{uuid.uuid4().hex[:4].upper()}",
            hypothesis_type="Business Email Compromise",
            description="Malicious spoofing or takeover of employee mailboxes to redirect funds.",
            supporting_evidence=evidence_ids,
            contradictory_evidence=contradictory,
            likelihood=round(max(0.05, min(0.95, bec_like - 0.1 * len(contradictory))), 2)
        ))

        # 7. Data Exfiltration
        de_like = 0.1
        if has_exfil:
            de_like += 0.7
        hypotheses.append(ThreatHypothesis(
            hypothesis_id=f"HYP-DE-{uuid.uuid4().hex[:4].upper()}",
            hypothesis_type="Data Exfiltration",
            description="Unauthorized copy or transmission of sensitive corporate/customer data.",
            supporting_evidence=evidence_ids,
            contradictory_evidence=contradictory,
            likelihood=round(max(0.05, min(0.95, de_like - 0.1 * len(contradictory))), 2)
        ))

        # 8. False Positive
        # False Positive likelihood is high only if there is weak evidence and positive whitelists
        fp_like = 0.15
        if not evidence_ids:
            fp_like += 0.55
        if contradictory:
            fp_like += 0.25
        if evidence_ids:
            fp_like -= 0.1 * len(evidence_ids)
        hypotheses.append(ThreatHypothesis(
            hypothesis_id=f"HYP-FP-{uuid.uuid4().hex[:4].upper()}",
            hypothesis_type="False Positive",
            description="Anomalies are verified benign behaviors matching standard user baseline variations.",
            supporting_evidence=contradictory,
            contradictory_evidence=evidence_ids,
            likelihood=round(max(0.05, min(0.95, fp_like)), 2)
        ))

        # 9. Unknown Threat Pattern
        utp_like = 0.2
        # If anomalies exist but no specific pattern triggers with high confidence
        all_likes = [ct_like, ato_like, ff_like, it_like, mi_like, bec_like, de_like]
        if max(all_likes) < 0.4 and evidence_ids:
            utp_like += 0.45
        hypotheses.append(ThreatHypothesis(
            hypothesis_id=f"HYP-UTP-{uuid.uuid4().hex[:4].upper()}",
            hypothesis_type="Unknown Threat Pattern",
            description="Observed indicators suggest a potential attack chain that does not match standard templates.",
            supporting_evidence=evidence_ids,
            contradictory_evidence=contradictory,
            likelihood=round(max(0.05, min(0.95, utp_like)), 2)
        ))

        # Rank by likelihood descending
        return sorted(hypotheses, key=lambda h: h.likelihood, reverse=True)
