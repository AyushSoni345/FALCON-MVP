from typing import List, Tuple
from src.models.node import Node

class GraphRulesEngine:
    def __init__(self):
        # Tuple: (source_node_type, target_node_type, relationship_type)
        self.rules = [
            # Identity & Device
            ("Customer", "Device", "USES"),
            ("Customer", "Account", "OWNS"),
            ("Customer", "Transaction", "PERFORMED_TRANSACTION"),
            ("Customer", "Session", "HAS_SESSION"),
            ("Customer", "User", "HAS_USER"),
            
            # Authentication & Session
            ("User", "Session", "CREATED_SESSION"),
            ("User", "Device", "LOGGED_IN_FROM"),
            ("Device", "Session", "ASSOCIATED_WITH"),
            
            # Network & Infrastructure
            ("Device", "IP Address", "CONNECTED_TO"),
            ("VPN", "IP Address", "CONNECTED_TO"),
            ("Device", "VPN", "CONNECTED_TO"),
            ("Device", "VPN Gateway", "CONNECTED_TO"),
            ("VPN Gateway", "IP Address", "CONNECTED_TO"),
            ("Endpoint", "IP Address", "CONNECTED_TO"),
            ("Server", "IP Address", "CONNECTED_TO"),
            ("Firewall", "IP Address", "MONITORS"),
            ("Device", "Firewall", "TRAVERSED_BY"),
            
            # Transactions
            ("Session", "Transaction", "INITIATED"),
            ("Transaction", "Beneficiary", "SENT_TO"),
            ("Transaction", "Account", "INVOLVED"),
            ("Transaction", "Merchant", "SENT_TO"),
            ("Transaction", "ATM", "INVOLVED"),
            ("Transaction", "POS", "INVOLVED"),
            
            # Endpoint & Threat
            ("Endpoint", "Process", "EXECUTED"),
            ("Endpoint", "Malware", "INFECTED_BY"),
            ("Device", "IOC", "COMMUNICATED_WITH"),
            ("Process", "Malware", "EXECUTED_MALWARE"),
            ("Endpoint", "Device", "ASSOCIATED_WITH"),
            
            # Security Events & SIEM Connections
            ("Firewall", "Event", "TRIGGERED"),
            ("SIEM", "Event", "COLLECTED"),
            ("SIEM", "Malware", "DETECTED"),
            ("Event", "Threat Actor", "MATCHED"),
            ("Event", "IP Address", "OCCURRED_ON"),
            ("Event", "User", "TRIGGERED_BY"),
            ("Event", "Device", "OCCURRED_ON"),
            ("Event", "Customer", "ASSOCIATED_WITH"),
            ("Event", "Endpoint", "ASSOCIATED_WITH"),
            ("Event", "Transaction", "ASSOCIATED_WITH"),
            ("SIEM", "Device", "MONITORS"),
            ("SIEM", "Endpoint", "MONITORS"),
            ("SIEM", "Server", "MONITORS"),
            ("SIEM", "Firewall", "MONITORS")
        ]

    def infer_relationships(self, nodes: List[Node]) -> List[Tuple[Node, Node, str]]:
        relationships_to_create = []
        for source in nodes:
            for target in nodes:
                if source.node_id == target.node_id:
                    continue
                for s_type, t_type, rel_type in self.rules:
                    if source.node_type == s_type and target.node_type == t_type:
                        relationships_to_create.append((source, target, rel_type))
        return relationships_to_create
