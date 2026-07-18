import logging
from typing import Any, Dict, List, Optional
from module5.models.input.incident import CorrelatedSecurityIncident, TimelineStep
from module5.models.output.assessment import SuspiciousTransaction, HighRiskBeneficiary, MuleAccountDetection, FraudAssessment

logger = logging.getLogger("FALCON.Module5.Fraud.Components")

class FraudContextExtractor:
    """
    Extracts financial and transaction context from the CorrelatedSecurityIncident.
    """
    def extract(self, incident: CorrelatedSecurityIncident) -> Dict[str, Any]:
        context = {
            "transactions": [],
            "beneficiary_events": [],
            "atm_withdrawals": [],
            "upi_transfers": [],
            "affected_accounts": incident.incident_context.affected_accounts or [],
            "affected_transactions": incident.incident_context.affected_transactions or [],
            "primary_entity": incident.incident_information.primary_entity,
            "has_high_value": False,
            "total_value": 0.0
        }

        # Parse timeline steps for financial events
        for step in incident.incident_timeline:
            action = step.action.upper()
            if "TRANSFER" in action or "TRANSACTION" in action or "PAYMENT" in action or "WITHDRAW" in action or "ATM" in action or "UPI" in action:
                # Mock transaction extraction
                val = 100000.0 # Default fallback amount if not parsing from text
                # Try parsing amount from description if possible
                for obs in incident.ai_reasoning.temporal_observations + [incident.ai_reasoning.anomaly_summary]:
                    if "₹" in obs or "Rs" in obs or "INR" in obs:
                        # Try parsing numbers (e.g. ₹5,00,000)
                        import re
                        m = re.search(r'(?:₹|Rs\.?|INR)\s*([\d,]+)', obs)
                        if m:
                            val = float(m.group(1).replace(",", ""))
                            break
                
                txn_data = {
                    "id": f"TXN-{step.event_uuid[:6].upper()}",
                    "type": step.action,
                    "amount": val,
                    "currency": "INR",
                    "timestamp": step.timestamp,
                    "sequence_number": step.sequence_number,
                    "entity": step.entity
                }
                context["transactions"].append(txn_data)
                context["total_value"] += val
                if val >= 200000.0:
                    context["has_high_value"] = True

                if "ATM" in action or "WITHDRAW" in action:
                    context["atm_withdrawals"].append(txn_data)
                if "UPI" in action or "TRANSFER" in action:
                    context["upi_transfers"].append(txn_data)

            if "BENEFICIARY" in action:
                context["beneficiary_events"].append({
                    "id": f"BEN-{step.event_uuid[:6].upper()}",
                    "action": step.action,
                    "timestamp": step.timestamp,
                    "entity": step.entity
                })

        return context


class TransactionAnalyzer:
    """
    Evaluates transactional parameters such as velocity, amounts, and sequences.
    """
    def analyze_transactions(self, context: Dict[str, Any], incident: CorrelatedSecurityIncident) -> List[SuspiciousTransaction]:
        suspicious = []
        
        # Build suspicious transactions list based on extracted context
        for i, tx in enumerate(context["transactions"]):
            risk_reason = "Atypical transaction for this account."
            severity = "MEDIUM"
            confidence = 80.0
            
            # Heuristics based on amount or original fraud indicators
            if tx["amount"] >= 500000.0:
                risk_reason = "High-value transfer exceeding normal threshold."
                severity = "HIGH"
                confidence = 90.0
            elif len(context["transactions"]) > 2:
                risk_reason = "Rapid transaction velocity (burst payment behavior)."
                severity = "HIGH"
                confidence = 85.0
            elif "dormant" in incident.ai_reasoning.anomaly_summary.lower():
                risk_reason = "Transaction initiated after long period of account dormancy."
                severity = "HIGH"
                confidence = 88.0

            suspicious.append(SuspiciousTransaction(
                transaction_id=tx["id"],
                transaction_type=tx["type"],
                amount=tx["amount"],
                currency=tx["currency"],
                risk_reason=risk_reason,
                severity=severity,
                confidence=confidence,
                timeline_reference=[tx["sequence_number"]],
                graph_reference=[node.node_id for node in incident.attack_graph.attack_nodes if tx["id"] in node.properties or tx["entity"] in node.node_id][:1]
            ))

        # Check ATM -> UPI correlation (e.g. within 10 minutes/600 seconds)
        for atm in context.get("atm_withdrawals", []):
            for upi in context.get("upi_transfers", []):
                if upi["timestamp"] > atm["timestamp"]:
                    diff = (upi["timestamp"] - atm["timestamp"]).total_seconds()
                    if 0 < diff <= 600:
                        existing = next((s for s in suspicious if s.transaction_id == upi["id"]), None)
                        risk_reason = f"ATM Withdrawal followed by rapid UPI Transfer within {diff:.1f}s (potential cash-out/mule layering)."
                        if existing:
                            existing.risk_reason = risk_reason
                            existing.severity = "HIGH"
                            existing.confidence = max(existing.confidence, 92.0)
                            if atm["sequence_number"] not in existing.timeline_reference:
                                existing.timeline_reference.append(atm["sequence_number"])
                        else:
                            suspicious.append(SuspiciousTransaction(
                                transaction_id=upi["id"],
                                transaction_type=upi["type"],
                                amount=upi["amount"],
                                currency=upi["currency"],
                                risk_reason=risk_reason,
                                severity="HIGH",
                                confidence=92.0,
                                timeline_reference=[atm["sequence_number"], upi["sequence_number"]],
                                graph_reference=[node.node_id for node in incident.attack_graph.attack_nodes if upi["id"] in node.properties or upi["entity"] in node.node_id][:1]
                            ))

        # Fallback if no transactions extracted but incident context indicates them
        if not suspicious and context["affected_transactions"]:
            for i, tx_id in enumerate(context["affected_transactions"]):
                suspicious.append(SuspiciousTransaction(
                    transaction_id=tx_id,
                    transaction_type="TRANSFER",
                    amount=150000.0,
                    currency="INR",
                    risk_reason="Linked to anomalous security incident timeline.",
                    severity="MEDIUM",
                    confidence=75.0,
                    timeline_reference=[1],
                    graph_reference=[]
                ))

        return suspicious


class BeneficiaryAnalyzer:
    """
    Analyzes beneficiary registration and modifications.
    """
    def analyze_beneficiaries(self, context: Dict[str, Any], incident: CorrelatedSecurityIncident) -> List[HighRiskBeneficiary]:
        high_risk = []
        
        # Check beneficiary actions
        for ev in context["beneficiary_events"]:
            linked_txs = [tx["id"] for tx in context["transactions"]]
            reason = "New beneficiary registered immediately before a high-value transfer." if "CREATE" in ev["action"].upper() or "ADD" in ev["action"].upper() else "Beneficiary modification preceding transaction."
            
            high_risk.append(HighRiskBeneficiary(
                beneficiary_id=ev["id"],
                beneficiary_type="INDIVIDUAL",
                beneficiary_risk_reason=reason,
                linked_transactions=linked_txs,
                confidence=85.0
            ))

        # Fallback if no events but implied in incident summary
        if not high_risk and "beneficiary" in incident.ai_reasoning.anomaly_summary.lower():
            high_risk.append(HighRiskBeneficiary(
                beneficiary_id="BEN-UNKNOWN",
                beneficiary_type="INDIVIDUAL",
                beneficiary_risk_reason="Newly added beneficiary associated with compromised session.",
                linked_transactions=[tx.transaction_id for tx in high_risk][:1],
                confidence=70.0
            ))

        return high_risk


class MuleAccountDetector:
    """
    Evaluates whether accounts behave like money mules.
    """
    def detect_mule(self, context: Dict[str, Any], incident: CorrelatedSecurityIncident) -> Optional[MuleAccountDetection]:
        # Search for indicators of money laundering/mules (e.g. dormant activation, layered transfers)
        is_mule = False
        reasons = []
        summary = incident.ai_reasoning.anomaly_summary.lower()
        
        if "mule" in summary or "rapid account draining" in summary or "layering" in summary:
            is_mule = True
            reasons.append("Account shows rapid in-and-out layering pattern typical of money mule activity.")
        
        # Heuristic: rapid transfers + high cumulative value on a new beneficiary
        if len(context["transactions"]) >= 3 and context["beneficiary_events"]:
            is_mule = True
            reasons.append("Multiple transactions routing funds to a newly added beneficiary in a short timeframe.")

        if is_mule:
            return MuleAccountDetection(
                detected=True,
                confidence=85.0,
                supporting_evidence=reasons,
                linked_accounts=context["affected_accounts"],
                linked_transactions=[tx["id"] for tx in context["transactions"]]
            )
        return None


class FraudPatternDetector:
    """
    Identifies high-level financial fraud patterns.
    """
    def detect_patterns(self, transactions: List[SuspiciousTransaction], beneficiaries: List[HighRiskBeneficiary], mule: Optional[MuleAccountDetection], incident: CorrelatedSecurityIncident) -> List[str]:
        patterns = []
        summary = incident.ai_reasoning.anomaly_summary.lower()

        if beneficiaries and transactions:
            patterns.append("Beneficiary Abuse")
        if "account takeover" in summary or "compromised" in summary:
            patterns.append("Account Takeover")
        if mule:
            patterns.append("Mule Network Activity")
            patterns.append("Rapid Fund Extraction")
        if len(transactions) > 2:
            patterns.append("Velocity Fraud")
        if "phishing" in summary or "scam" in summary:
            patterns.append("Authorized Push Payment Fraud")
        if any("ATM Withdrawal followed by rapid UPI" in tx.risk_reason for tx in transactions):
            patterns.append("ATM-to-UPI Cashout Correlation")

        # Deduplicate
        return list(set(patterns))


class FraudRiskCalculator:
    """
    Calculates the transaction risk sub-score (0-100) and confidence.
    """
    def calculate(self, transactions: List[SuspiciousTransaction], beneficiaries: List[HighRiskBeneficiary], mule: Optional[MuleAccountDetection], incident_confidence: float) -> tuple[float, float]:
        if not transactions and not beneficiaries:
            return 0.0, 0.0

        # Heuristic scoring based on severity
        severity_values = {"LOW": 20, "MEDIUM": 55, "HIGH": 85, "CRITICAL": 98}
        total_risk = 0.0
        max_risk = 0.0

        for tx in transactions:
            val = severity_values.get(tx.severity.upper(), 55)
            total_risk += val
            if val > max_risk:
                max_risk = val

        for ben in beneficiaries:
            total_risk += 60.0
            if max_risk < 60.0:
                max_risk = 60.0

        if mule:
            max_risk = max(max_risk, 90.0)
            total_risk += 90.0

        total_elements = len(transactions) + len(beneficiaries) + (1 if mule else 0)
        avg_risk = total_risk / total_elements if total_elements > 0 else 0.0
        
        # Risk score combines max and average
        risk_score = min((max_risk * 0.75) + (avg_risk * 0.25), 100.0)

        # Confidence combining incident confidence + engine indicators
        base_confidence = 80.0
        if transactions:
            base_confidence = sum(t.confidence for t in transactions) / len(transactions)
        
        confidence = (base_confidence * 0.6) + (incident_confidence * 100 * 0.4)
        confidence = min(max(confidence, 0.0), 100.0)

        return round(risk_score, 2), round(confidence, 2)


class FraudSignalGenerator:
    """
    Generates shared signals for other engines.
    """
    def generate_signals(self, patterns: List[str], transactions: List[SuspiciousTransaction], mule: Optional[MuleAccountDetection]) -> List[str]:
        signals = []
        if "Account Takeover" in patterns:
            signals.append("Account Takeover Suspicion")
        if "Beneficiary Abuse" in patterns:
            signals.append("Beneficiary Abuse Attempt")
        if mule:
            signals.append("Mule Account Suspicion")
        if any(tx.amount >= 500000.0 for tx in transactions):
            signals.append("High-Value Transfer Activity")
        if "Rapid Fund Extraction" in patterns:
            signals.append("Rapid Account Extraction Pattern")

        return signals


class FraudRecommendationGenerator:
    """
    Suggests advisory actions for transaction mitigation.
    """
    def generate_recommendations(self, patterns: List[str], transactions: List[SuspiciousTransaction], mule: Optional[MuleAccountDetection]) -> List[str]:
        recommendations = []
        
        if transactions:
            recommendations.append("Place transaction hold and review transfer legitimacy.")
        if "Beneficiary Abuse" in patterns:
            recommendations.append("Freeze newly registered beneficiary accounts.")
        if mule:
            recommendations.append("Investigate destination accounts for association with mule networks.")
            recommendations.append("Freeze outbound accounts immediately.")
        
        recommendations.append("Initiate customer validation call/out-of-band contact.")
        return list(set(recommendations))


class FraudAssessmentBuilder:
    """
    Assembles final FraudAssessment output model.
    """
    def build(self, patterns: List[str], transactions: List[SuspiciousTransaction], beneficiaries: List[HighRiskBeneficiary], mule: Optional[MuleAccountDetection], risk_score: float, confidence: float, evidence: List[str]) -> FraudAssessment:
        return FraudAssessment(
            fraud_patterns=patterns,
            suspicious_transactions=transactions,
            high_risk_beneficiaries=beneficiaries,
            mule_account_detected=mule,
            transaction_risk_score=risk_score,
            confidence=confidence,
            supporting_evidence=evidence
        )
