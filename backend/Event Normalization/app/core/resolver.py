import logging
from typing import Dict, Any, Optional
from app.core.schema import UniversalEventEnvelope
from app.core.parsers.base import get_case_insensitive
from app.logging_config import log_pipeline

class BoundedDict(dict):
    def __init__(self, max_size: int = 10000, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.max_size = max_size

    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        if len(self) > self.max_size:
            first_key = next(iter(self))
            del self[first_key]

class IdentityResolver:
    """
    Correlates and resolves identity attributes across banking systems and security logs.
    Ensures resolution priority: entity_context -> normalized_data -> raw_payload.
    """

    def __init__(self):
        # Bounded in-memory relationship mapping tables
        self.session_to_customer = BoundedDict(max_size=10000)
        self.session_to_username = BoundedDict(max_size=10000)
        self.username_to_employee = BoundedDict(max_size=10000)
        self.ip_to_username = BoundedDict(max_size=10000)
        self.account_to_customer = BoundedDict(max_size=10000)
        self.device_to_customer = BoundedDict(max_size=10000)

    def _mask(self, val: Any) -> str:
        if not val:
            return "None"
        val_str = str(val)
        if len(val_str) <= 4:
            return "****"
        return f"{val_str[:2]}****{val_str[-2:]}"

    def resolve(self, uee: UniversalEventEnvelope, normalized_event: Dict[str, Any]) -> Dict[str, Any]:
        ident = normalized_event["identity_context"]
        ec = uee.entity_context
        rp = uee.raw_payload or {}
        
        event_uuid = uee.metadata.event_uuid
        corr_id = uee.metadata.correlation_id

        log_pipeline(
            logging.DEBUG,
            "Performing identity correlation checks.",
            "identity_resolution",
            "started",
            event_uuid=event_uuid,
            correlation_id=corr_id
        )

        # 1. Resolve each identity field strictly following priority: entity_context -> normalized_data -> raw_payload
        customer_id = ec.customer_id or ident.get("customer_id") or get_case_insensitive(rp, ["customer_id", "CustomerID", "CustID"])
        employee_id = ec.employee_id or ident.get("employee_id") or get_case_insensitive(rp, ["employee_id", "EmployeeID", "EmpID"])
        username = ec.username or ident.get("username") or get_case_insensitive(rp, ["username", "userName", "Username"])
        session_id = ec.session_id or ident.get("session_id") or get_case_insensitive(rp, ["session_id", "sessionId", "SessionID"])
        device_id = ec.device_id or ident.get("device_id") or get_case_insensitive(rp, ["device_id", "DeviceID", "deviceId"])
        account_number = ec.account_number or ident.get("account_number") or get_case_insensitive(rp, ["account_number", "AccountNumber", "accountNumber"])
        card_number_masked = ec.card_number_masked or ident.get("card_number_masked") or get_case_insensitive(rp, ["card_number", "card_number_masked", "CardNumber"])
        beneficiary_id = ec.beneficiary_id or ident.get("beneficiary_id") or get_case_insensitive(rp, ["beneficiary_id", "beneficiaryId", "BeneficiaryID"])
        endpoint_id = ec.endpoint_id or ident.get("endpoint_id") or get_case_insensitive(rp, ["endpoint_id", "endpointId", "EndpointID", "host_id"])
        user_id = ec.user_id or ident.get("user_id") or get_case_insensitive(rp, ["user_id", "userId", "UserID"])
        ip_address = ident.get("ip_address") or uee.network_context.source_ip or get_case_insensitive(rp, ["ip", "ip_address", "Client_IP", "SRC_IP", "Login_IP"])

        # 2. Update relationship maps from the resolved fields
        if session_id:
            if customer_id:
                self.session_to_customer[session_id] = customer_id
            if username:
                self.session_to_username[session_id] = username
                
        if username and employee_id:
            self.username_to_employee[username] = employee_id
            
        if ip_address and username:
            self.ip_to_username[ip_address] = username
            
        if account_number and customer_id:
            self.account_to_customer[account_number] = customer_id
            
        if device_id and customer_id:
            self.device_to_customer[device_id] = customer_id

        # 3. Correlate and fill missing identity fields using relationship history
        if not customer_id:
            if session_id and session_id in self.session_to_customer:
                customer_id = self.session_to_customer[session_id]
                log_pipeline(
                    logging.DEBUG,
                    f"Resolved customer_id: {customer_id} from session_id history",
                    "identity_resolution",
                    "in_progress",
                    event_uuid=event_uuid,
                    correlation_id=corr_id
                )
            elif account_number and account_number in self.account_to_customer:
                customer_id = self.account_to_customer[account_number]
                log_pipeline(
                    logging.DEBUG,
                    f"Resolved customer_id: {customer_id} from account_number history",
                    "identity_resolution",
                    "in_progress",
                    event_uuid=event_uuid,
                    correlation_id=corr_id
                )
            elif device_id and device_id in self.device_to_customer:
                customer_id = self.device_to_customer[device_id]
                log_pipeline(
                    logging.DEBUG,
                    f"Resolved customer_id: {customer_id} from device_id history",
                    "identity_resolution",
                    "in_progress",
                    event_uuid=event_uuid,
                    correlation_id=corr_id
                )

        if not username:
            if session_id and session_id in self.session_to_username:
                username = self.session_to_username[session_id]
            elif ip_address and ip_address in self.ip_to_username:
                username = self.ip_to_username[ip_address]

        if not employee_id and username:
            if username in self.username_to_employee:
                employee_id = self.username_to_employee[username]

        # 4. Set resolved fields back into the event dictionary (Sensitive values are masked in log message)
        ident["customer_id"] = str(customer_id) if customer_id else None
        ident["employee_id"] = str(employee_id) if employee_id else None
        ident["username"] = str(username) if username else None
        ident["session_id"] = str(session_id) if session_id else None
        ident["device_id"] = str(device_id) if device_id else None
        ident["account_number"] = str(account_number) if account_number else None
        ident["card_number_masked"] = str(card_number_masked) if card_number_masked else None
        ident["beneficiary_id"] = str(beneficiary_id) if beneficiary_id else None
        ident["endpoint_id"] = str(endpoint_id) if endpoint_id else None
        ident["user_id"] = str(user_id) if user_id else None
        ident["ip_address"] = str(ip_address) if ip_address else None

        masked_account = self._mask(account_number)
        log_pipeline(
            logging.DEBUG,
            f"Resolved Identity Profile: Username={username}, CustID={customer_id}, Account={masked_account}",
            "identity_resolution",
            "success",
            event_uuid=event_uuid,
            correlation_id=corr_id
        )

        return normalized_event
