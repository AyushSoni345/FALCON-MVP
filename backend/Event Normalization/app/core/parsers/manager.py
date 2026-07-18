import logging
import time
from typing import Dict, Any, Optional
from app.core.parsers.base import BaseParser
from app.core.schema import UniversalEventEnvelope
from app.core.parsers.firewall import FirewallParser
from app.core.parsers.ids import IDSParser
from app.core.parsers.vpn import VPNParser
from app.core.parsers.iam import IAMParser
from app.core.parsers.internet_banking import InternetBankingParser
from app.core.parsers.core_banking import CoreBankingParser
from app.core.parsers.upi import UPIParser
from app.core.parsers.neft_rtgs_imps import NEFTParser, RTGSParser, IMPSParser
from app.core.parsers.card import CardParser
from app.core.parsers.atm import ATMParser
from app.core.parsers.beneficiary import BeneficiaryParser
from app.core.parsers.edr import EDRParser
from app.core.parsers.siem import SIEMParser
from app.core.parsers.threat_feed import ThreatFeedParser
from app.core.parsers.quantum import QuantumParser
from app.logging_config import log_pipeline

class ParserManager:
    """
    Registry and Selection Engine for event parsers.
    Dynamically loads and invokes parsers using metadata.event_type.
    """

    def __init__(self):
        self._parsers: Dict[str, BaseParser] = {
            "FIREWALL": FirewallParser(),
            "IDS": IDSParser(),
            "VPN": VPNParser(),
            "IAM": IAMParser(),
            "INTERNET_BANKING": InternetBankingParser(),
            "CORE_BANKING": CoreBankingParser(),
            "UPI": UPIParser(),
            "NEFT": NEFTParser(),
            "RTGS": RTGSParser(),
            "IMPS": IMPSParser(),
            "CARD": CardParser(),
            "ATM": ATMParser(),
            "BENEFICIARY": BeneficiaryParser(),
            "EDR": EDRParser(),
            "SIEM": SIEMParser(),
            "THREAT_FEED": ThreatFeedParser(),
            "QUANTUM": QuantumParser(),
            "ENDPOINT": EDRParser()
        }
        
        # Dynamically wrap all parsers' normalize methods with pipeline trace logs
        for parser in self._parsers.values():
            self._wrap_parser(parser)

    def _wrap_parser(self, parser: BaseParser):
        original_normalize = parser.normalize
        parser_name = parser.__class__.__name__

        def wrapped_normalize(uee: UniversalEventEnvelope) -> Dict[str, Any]:
            event_uuid = uee.metadata.event_uuid
            corr_id = uee.metadata.correlation_id
            
            log_pipeline(
                logging.DEBUG,
                f"Parser Started",
                "parser_execution",
                "started",
                event_uuid=event_uuid,
                correlation_id=corr_id,
                parser_name=parser_name
            )
            
            start = time.perf_counter()
            result = original_normalize(uee)
            dur = (time.perf_counter() - start) * 1000.0
            
            log_pipeline(
                logging.DEBUG,
                f"Parser Completed",
                "parser_execution",
                "success",
                event_uuid=event_uuid,
                correlation_id=corr_id,
                duration=dur,
                parser_name=parser_name
            )
            return result

        parser.normalize = wrapped_normalize

    def get_parser(self, event_type: str) -> Optional[BaseParser]:
        normalized_type = str(event_type).upper().strip()
        log_pipeline(
            logging.DEBUG,
            f"Checking parser registry lookup for: {normalized_type}",
            "parser_selection",
            "started"
        )
        parser = self._parsers.get(normalized_type)
        if parser:
            log_pipeline(
                logging.DEBUG,
                f"Parser registry match found: {parser.__class__.__name__}",
                "parser_selection",
                "success"
            )
        else:
            log_pipeline(
                logging.WARNING,
                f"No parser matched registry lookup for: {normalized_type}",
                "parser_selection",
                "failed"
            )
        return parser
