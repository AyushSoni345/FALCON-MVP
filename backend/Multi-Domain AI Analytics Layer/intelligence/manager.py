import logging
from enum import Enum
from typing import Dict, List, Set
from module5.models.shared.engine_result import EngineResult

logger = logging.getLogger("FALCON.Module5.Intelligence.Manager")

class SignalCategory(str, Enum):
    CREDENTIAL_MISUSE = "CREDENTIAL_MISUSE"
    SESSION_ABUSE = "SESSION_ABUSE"
    BEHAVIOURAL_DRIFT = "BEHAVIOURAL_DRIFT"
    
    CREDENTIAL_COMPROMISE = "CREDENTIAL_COMPROMISE"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    MALWARE_INFECTION = "MALWARE_INFECTION"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    
    ACCOUNT_TAKEOVER = "ACCOUNT_TAKEOVER"
    BENEFICIARY_ABUSE = "BENEFICIARY_ABUSE"
    MULE_ACCOUNT = "MULE_ACCOUNT"
    RAPID_TRANSFER = "RAPID_TRANSFER"
    
    BULK_ENCRYPTED_TRANSFER = "BULK_ENCRYPTED_TRANSFER"
    CRYPTOGRAPHIC_ENUMERATION = "CRYPTOGRAPHIC_ENUMERATION"
    HNDL_DETECTION = "HNDL_DETECTION"
    LONG_LIVED_SESSION = "LONG_LIVED_SESSION"
    UNKNOWN = "UNKNOWN"

def classify_signal(sig: str) -> SignalCategory:
    sig_lower = sig.lower()
    
    # Behaviour
    if "travel" in sig_lower or "impossible travel" in sig_lower:
        return SignalCategory.CREDENTIAL_MISUSE
    if "new device" in sig_lower:
        return SignalCategory.CREDENTIAL_MISUSE
    if "misuse" in sig_lower:
        return SignalCategory.CREDENTIAL_MISUSE
    if "concurrent session" in sig_lower or "session activity" in sig_lower:
        return SignalCategory.SESSION_ABUSE
    if "drift" in sig_lower:
        return SignalCategory.BEHAVIOURAL_DRIFT
        
    # Cyber
    if "credential compromise" in sig_lower:
        return SignalCategory.CREDENTIAL_COMPROMISE
    if "lateral" in sig_lower or "movement" in sig_lower:
        return SignalCategory.LATERAL_MOVEMENT
    if "malware" in sig_lower:
        return SignalCategory.MALWARE_INFECTION
    if "privilege" in sig_lower or "escalation" in sig_lower:
        return SignalCategory.PRIVILEGE_ESCALATION
        
    # Quantum
    if "bulk" in sig_lower or "encrypted transfer" in sig_lower:
        return SignalCategory.BULK_ENCRYPTED_TRANSFER
    if "cryptographic" in sig_lower or "enumeration" in sig_lower:
        return SignalCategory.CRYPTOGRAPHIC_ENUMERATION
    if "harvest" in sig_lower or "hndl" in sig_lower:
        return SignalCategory.HNDL_DETECTION
    if "long-lived" in sig_lower or "session detected" in sig_lower:
        return SignalCategory.LONG_LIVED_SESSION

    # Fraud
    if "takeover" in sig_lower:
        return SignalCategory.ACCOUNT_TAKEOVER
    if "beneficiary" in sig_lower:
        return SignalCategory.BENEFICIARY_ABUSE
    if "mule" in sig_lower:
        return SignalCategory.MULE_ACCOUNT
    if "high-value" in sig_lower or "transfer" in sig_lower or "extraction" in sig_lower:
        return SignalCategory.RAPID_TRANSFER
        
    return SignalCategory.UNKNOWN

class CrossDomainIntelligenceManager:
    """
    Manages loose cross-domain communication between analytics engines.
    Aggregates signals from first-pass evaluations and distributes them to target engines.
    """
    def __init__(self):
        # Maps source engine signals to target engines
        self._routing_map = {
            # Behaviour signals
            "Impossible Travel Detected": ["Fraud", "Cyber"],
            "Credential Misuse (New Device)": ["Fraud", "Cyber"],
            "Credential Misuse Detected": ["Fraud", "Cyber"],
            "Behavioural Drift Observed": ["Fraud"],
            "Concurrent Session Activity": ["Cyber", "Fraud"],
            
            # Cyber signals
            "Credential Compromise Detected": ["Behaviour", "Fraud"],
            "Lateral Movement Detected": ["Behaviour", "Fraud", "Quantum"],
            "Malware Detected": ["Behaviour", "Fraud"],
            "Privilege Escalation Detected": ["Behaviour", "Fraud"],
            "C2/Data Exfiltration Risk": ["Quantum"],
            
            # Fraud signals
            "Account Takeover Suspicion": ["Behaviour", "Cyber"],
            "Mule Account Suspicion": ["Behaviour"],
            "Beneficiary Abuse Attempt": ["Behaviour", "Cyber"],
            "High-Value Transfer Activity": ["Behaviour", "Cyber"],
            "Rapid Account Extraction Pattern": ["Behaviour", "Cyber"],
            
            # Quantum signals
            "Bulk Encrypted Data Transfer Detected": ["Cyber"],
            "Cryptographic Asset Enumeration Alert": ["Cyber"],
            "Harvest-Now-Decrypt-Later Staged Data": ["Cyber"],
            "Long-Lived Encrypted Session Detected": ["Cyber"]
        }

    def route_signals(self, first_pass_results: List[EngineResult]) -> Dict[str, List[str]]:
        """
        Consolidates signals from the first-pass results of all engines
        and returns a mapping of target engine name -> list of routing signals.
        """
        logger.info("Starting cross-domain intelligence signal routing.")
        signals_by_target: Dict[str, List[str]] = {
            "Behaviour": [],
            "Fraud": [],
            "Cyber": [],
            "Quantum": []
        }

        routed_count = 0
        for result in first_pass_results:
            source_engine = result.engine_name
            for sig in result.shared_signals:
                targets = self._routing_map.get(sig, [])
                for target in targets:
                    # Do not route a signal back to its source engine
                    if target != source_engine:
                        if sig not in signals_by_target[target]:
                            signals_by_target[target].append(f"{source_engine} shared: {sig}")
                            routed_count += 1

        logger.info(f"Routed {routed_count} cross-domain signals to target engines.")
        return signals_by_target
