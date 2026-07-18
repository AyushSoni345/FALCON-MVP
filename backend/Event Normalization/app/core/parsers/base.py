from abc import ABC, abstractmethod
from typing import Dict, Any, List
from app.core.schema import UniversalEventEnvelope

def get_case_insensitive(d: Dict[str, Any], keys: List[str], default: Any = None) -> Any:
    """Helper to extract values from a dictionary using a list of potential keys in case-insensitive manner."""
    if not isinstance(d, dict):
        return default
    for key in keys:
        if key in d:
            return d[key]
        for k, v in d.items():
            if k.lower() == key.lower():
                return v
    return default

def normalize_severity(raw_sev: Any) -> str:
    if not raw_sev:
        return "LOW"
    raw_sev_str = str(raw_sev).upper()
    if raw_sev_str in ["CRITICAL", "FATAL", "9", "10"]:
        return "CRITICAL"
    if raw_sev_str in ["HIGH", "ERROR", "7", "8"]:
        return "HIGH"
    if raw_sev_str in ["MEDIUM", "WARN", "WARNING", "5", "6"]:
        return "MEDIUM"
    return "LOW"

class BaseParser(ABC):
    """
    Standard interface for all event-specific log parsers.
    Processes raw vendor-specific event parameters into normalized structures.
    """

    @abstractmethod
    def normalize(self, uee: UniversalEventEnvelope) -> Dict[str, Any]:
        """
        Transforms the raw event logs inside the Universal Event Envelope into the canonical enterprise structure.
        """
        pass

    def validate(self, uee: UniversalEventEnvelope) -> bool:
        """
        Default validation checks that envelope contexts are present. Can be overridden.
        """
        return uee.metadata is not None

    def extract_identity(self, uee: UniversalEventEnvelope) -> Dict[str, Any]:
        """
        Extracts identity parameters with priority: entity_context -> raw_payload.
        """
        ec = uee.entity_context
        rp = uee.raw_payload or {}
        
        return {
            "customer_id": ec.customer_id or get_case_insensitive(rp, ["customer_id", "CustomerID", "CustID", "customerId"]),
            "employee_id": ec.employee_id or get_case_insensitive(rp, ["employee_id", "employeeId", "EmployeeID", "EmpID"]),
            "user_id": ec.user_id or get_case_insensitive(rp, ["user_id", "userId", "UserID"]),
            "username": ec.username or get_case_insensitive(rp, ["username", "userName", "Username", "user"]),
            "account_number": ec.account_number or get_case_insensitive(rp, ["account_number", "accountNumber", "AccountNumber", "account_no"]),
            "card_number_masked": ec.card_number_masked or get_case_insensitive(rp, ["card_number", "cardNumber", "Card_Number", "CardNumber"]),
            "customer_type": get_case_insensitive(rp, ["customer_type", "customerType", "user_type"]),
            "role": get_case_insensitive(rp, ["role", "user_role", "employee_role"]),
            "department": get_case_insensitive(rp, ["department", "dept"]),
            "authentication_method": get_case_insensitive(rp, ["authentication_method", "auth_method", "method"]),
            "authentication_status": get_case_insensitive(rp, ["authentication_status", "status", "login_status", "result"]),
            "mfa_status": get_case_insensitive(rp, ["mfa_status", "mfa", "mfa_used"]),
            # Helper keys to prevent parser KeyErrors:
            "beneficiary_id": ec.beneficiary_id or get_case_insensitive(rp, ["beneficiary_id", "beneficiaryId", "BeneficiaryID"]),
            "device_id": ec.device_id or get_case_insensitive(rp, ["device_id", "deviceId", "DeviceID"]),
            "endpoint_id": ec.endpoint_id or get_case_insensitive(rp, ["endpoint_id", "endpointId", "EndpointID"]),
            "session_id": ec.session_id or get_case_insensitive(rp, ["session_id", "sessionId", "SessionID"]),
            "ip_address": uee.network_context.source_ip or get_case_insensitive(rp, ["ip", "ip_address", "Client_IP", "SRC_IP", "Login_IP"])
        }

    def extract_assets(self, uee: UniversalEventEnvelope) -> Dict[str, Any]:
        """
        Extracts asset parameters from entity context and raw payload.
        """
        ec = uee.entity_context
        rp = uee.raw_payload or {}
        
        device_id = ec.device_id or get_case_insensitive(rp, ["device_id", "DeviceID", "deviceId"])
        endpoint_id = ec.endpoint_id or get_case_insensitive(rp, ["endpoint_id", "endpointId", "EndpointID"])
        
        return {
            "device_id": device_id,
            "endpoint_id": endpoint_id,
            "device_type": get_case_insensitive(rp, ["device_type", "deviceType"]),
            "operating_system": get_case_insensitive(rp, ["operating_system", "os", "operatingSystem"]),
            "browser": get_case_insensitive(rp, ["browser", "user_agent", "userAgent"]),
            "firewall": uee.security_context.firewall_device or get_case_insensitive(rp, ["firewall", "firewall_device", "fw"]),
            "vpn_gateway": get_case_insensitive(rp, ["vpn_gateway", "vpnGateway", "gateway"]),
            "atm_id": get_case_insensitive(rp, ["atm_id", "atmId", "ATM_ID"]),
            "pos_terminal": get_case_insensitive(rp, ["pos_terminal", "posId", "POS"]),
            "server_id": get_case_insensitive(rp, ["server_id", "serverId", "ServerID", "host_id"]),
            "asset_name": get_case_insensitive(rp, ["asset_name", "host", "hostname"]),
            "asset_group": get_case_insensitive(rp, ["asset_group", "group"]),
            "asset_location": get_case_insensitive(rp, ["asset_location", "location"]),
            "asset_owner": get_case_insensitive(rp, ["asset_owner", "owner"]),
            "asset_criticality": get_case_insensitive(rp, ["asset_criticality", "criticality", "priority"])
        }
