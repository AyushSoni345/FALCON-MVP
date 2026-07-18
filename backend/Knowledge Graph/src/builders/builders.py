import uuid
from typing import List, Union, Dict
from src.models.input_event import ContextEnrichedEvent
from src.models.node import Node
from src.builders.base_builder import BaseBuilder

class GenericBuilder(BaseBuilder):
    def __init__(self, context_key: str, mappings: Dict[str, Union[str, List[str]]]):
        self.context_key = context_key
        self.mappings = mappings # Dict[node_type, attr_key_or_list]

    def build_nodes(self, event: ContextEnrichedEvent) -> List[Node]:
        nodes = []
        extra = event.model_extra or {}
        
        # Try to find context using the exact key
        context = extra.get(self.context_key, {})
        
        # Fallback names mapping for compatibility:
        fallbacks = {
            "identity_context": ["Identity Context"],
            "asset_context": ["Asset Context", "Device Context"],
            "relationship_context": ["Relationship Context", "Session Context"],
            "financial_context": ["Financial Context"],
            "network_context": ["Network Context"],
            "threat_context": ["Threat Context"]
        }
        
        if not context:
            keys_to_try = fallbacks.get(self.context_key, [])
            # Also try auto-converting snake_case to Title Case
            if "_" in self.context_key:
                title_key = " ".join(word.capitalize() for word in self.context_key.split("_"))
                if title_key not in keys_to_try:
                    keys_to_try.append(title_key)
            
            for k in keys_to_try:
                context = extra.get(k, {})
                if context:
                    break

        if not isinstance(context, dict):
            context = {}
            
        for node_type, attr_keys in self.mappings.items():
            keys = [attr_keys] if isinstance(attr_keys, str) else attr_keys
            for attr_key in keys:
                val = context.get(attr_key) or extra.get(attr_key)
                if val:
                    nodes.append(Node(
                        node_id=str(uuid.uuid4()), 
                        node_type=node_type,
                        attributes={attr_key: val}
                    ))
        return nodes

class IdentityBuilder(GenericBuilder):
    def __init__(self):
        super().__init__("identity_context", {
            "Customer": "customer_id", 
            "User": "user_id", 
            "Employee": "employee_id"
        })

class DeviceBuilder(GenericBuilder):
    def __init__(self):
        super().__init__("asset_context", {
            "Device": "device_id", 
            "Browser": ["browser", "browser_id"]
        })

class SessionBuilder(GenericBuilder):
    def __init__(self):
        super().__init__("relationship_context", {
            "Session": "session_id"
        })

class TransactionBuilder(GenericBuilder):
    def __init__(self):
        super().__init__("financial_context", {
            "Transaction": "transaction_id", 
            "Beneficiary": "beneficiary_id", 
            "Account": ["account_number", "sender_account", "receiver_account"],
            "Merchant": "merchant",
            "ATM": "atm_id",
            "POS": ["pos_id", "pos_terminal_id", "pos_terminal"]
        })

class NetworkBuilder(GenericBuilder):
    def __init__(self):
        super().__init__("network_context", {
            "IP Address": ["source_ip", "destination_ip", "public_ip"], 
            "VPN": ["vpn_ip", "vpn_used"],
            "ASN": "asn",
            "Country": "country",
            "City": "city",
            "Domain": ["domain", "url", "malicious_domain"]
        })

class ThreatBuilder(GenericBuilder):
    def __init__(self):
        super().__init__("threat_context", {
            "Malware": ["malware_hash", "malicious_hash", "process_hash"], 
            "IOC": ["ioc", "IOC_value", "malicious_ip", "malicious_domain"], 
            "Threat Actor": "threat_actor"
        })

class AssetBuilder(GenericBuilder):
    def __init__(self):
        super().__init__("asset_context", {
            "Endpoint": "endpoint_id", 
            "Firewall": ["firewall_id", "firewall"], 
            "Server": "server_id", 
            "Process": "process_id",
            "VPN Gateway": "vpn_gateway_id"
        })

class SecurityLogBuilder(BaseBuilder):
    def build_nodes(self, event: ContextEnrichedEvent) -> List[Node]:
        nodes = []
        extra = event.model_extra or {}
        
        # Extract Event node
        event_id = event.event_uuid or extra.get("event_uuid") or extra.get("event_id")
        if event_id:
            nodes.append(Node(
                node_id=str(uuid.uuid4()),
                node_type="Event",
                attributes={"event_id": event_id}
            ))
            
        # Extract SIEM node
        siem_id = extra.get("siem_id")
        if siem_id:
            nodes.append(Node(
                node_id=str(uuid.uuid4()),
                node_type="SIEM",
                attributes={"siem_id": siem_id}
            ))
            
        return nodes
