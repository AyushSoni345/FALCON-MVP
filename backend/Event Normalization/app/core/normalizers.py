import uuid
from typing import Dict, Any, Optional
from app.utils.datetime_utils import normalize_to_iso8601

def get_case_insensitive(d: Dict[str, Any], keys: list, default=None) -> Any:
    """Helper to extract values from dict using a list of potential keys in case-insensitive manner."""
    for key in keys:
        if key in d:
            return d[key]
        # Case insensitive check
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

def normalize_event(raw: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main normalization entry point. Translates raw dictionaries into common schema fields.
    """
    # Extract metadata
    event_type = get_case_insensitive(raw, ["event_type", "eventType", "type"], "UNKNOWN")
    source_system = get_case_insensitive(raw, ["source_system", "sourceSystem", "source"], "UNKNOWN")
    orig_ts = get_case_insensitive(raw, ["timestamp", "time", "datetime", "date"])
    norm_ts = normalize_to_iso8601(orig_ts)
    
    event_id = get_case_insensitive(raw, ["event_id", "eventId"], str(uuid.uuid4()))
    correlation_id = get_case_insensitive(raw, ["correlation_id", "correlationId", "CorrelationID"])
    session_id = get_case_insensitive(raw, ["session_id", "sessionId", "SessionID"])
    
    # Extract identity fields
    customer_id = get_case_insensitive(raw, ["customer_id", "customerId", "CustomerID", "CustID"])
    employee_id = get_case_insensitive(raw, ["employee_id", "employeeId", "EmployeeID", "EmpID"])
    username = get_case_insensitive(raw, ["username", "userName", "Username"])
    device_id = get_case_insensitive(raw, ["device_id", "deviceId", "DeviceID"])
    account_number = get_case_insensitive(raw, ["account_number", "accountNumber", "AccountNumber", "account_no", "acc_num"])
    beneficiary_id = get_case_insensitive(raw, ["beneficiary_id", "beneficiaryId", "BeneficiaryID"])
    endpoint_id = get_case_insensitive(raw, ["endpoint_id", "endpointId", "EndpointID", "host_id", "hostId"])
    
    # Resolve primary IP address based on type
    ip_keys = ["ip", "ip_address", "ipAddress", "ip_addr", "IP"]
    if event_type.lower() == "firewall":
        ip_keys = ["SRC_IP", "src_ip", "source_ip"] + ip_keys
    elif event_type.lower() == "vpn":
        ip_keys = ["Client_IP", "client_ip", "vpn_ip"] + ip_keys
    elif event_type.lower() == "internet banking" or event_type.lower() == "internet_banking":
        ip_keys = ["Login_IP", "login_ip"] + ip_keys
    elif event_type.lower() == "atm":
        ip_keys = ["atm_ip", "ip"] + ip_keys
        
    ip_address = get_case_insensitive(raw, ip_keys)
    
    # Extract network fields
    src_ip = get_case_insensitive(raw, ["SRC_IP", "src_ip", "source_ip", "Client_IP", "client_ip", "Login_IP", "login_ip"])
    if not src_ip and ip_address:
        src_ip = ip_address
    dst_ip = get_case_insensitive(raw, ["DST_IP", "dst_ip", "destination_ip", "server_ip", "serverIp"])
    src_port = get_case_insensitive(raw, ["SRC_PORT", "src_port", "source_port", "sport"])
    dst_port = get_case_insensitive(raw, ["DST_PORT", "dst_port", "destination_port", "dport"])
    protocol = get_case_insensitive(raw, ["PROTO", "protocol", "proto"])
    direction = get_case_insensitive(raw, ["direction", "flow_direction"])
    bytes_sent = get_case_insensitive(raw, ["bytes_sent", "sent_bytes", "bytesSent"])
    bytes_received = get_case_insensitive(raw, ["bytes_received", "recv_bytes", "bytesReceived"])
    
    # Extract device fields
    device_name = get_case_insensitive(raw, ["device_name", "deviceName"])
    device_type = get_case_insensitive(raw, ["device_type", "deviceType"])
    if not device_type:
        # Heuristic device types
        evt_type_lower = event_type.lower()
        if "atm" in evt_type_lower:
            device_type = "ATM"
        elif "banking" in evt_type_lower or "card" in evt_type_lower:
            device_type = "Mobile"  # Mobile/POS default
        elif "edr" in evt_type_lower or "xdr" in evt_type_lower or "vpn" in evt_type_lower:
            device_type = "Laptop"
        elif "firewall" in evt_type_lower:
            device_type = "Firewall"
            
    os = get_case_insensitive(raw, ["os", "operating_system", "operatingSystem"])
    browser = get_case_insensitive(raw, ["browser", "user_agent", "userAgent"])
    
    # Extract transaction fields
    transaction_id = get_case_insensitive(raw, ["transaction_id", "transactionId", "TransactionID"])
    amount_raw = get_case_insensitive(raw, ["amount", "amt", "value"])
    amount = None
    if amount_raw is not None:
        try:
            amount = float(amount_raw)
        except (ValueError, TypeError):
            pass
            
    currency = get_case_insensitive(raw, ["currency", "curr"], "INR" if amount is not None else None)
    merchant_name = get_case_insensitive(raw, ["merchant", "merchant_name", "merchantName"])
    transaction_type = get_case_insensitive(raw, ["transaction_type", "transactionType"])
    if not transaction_type and amount is not None:
        # derive transaction type from event type
        if "upi" in event_type.lower():
            transaction_type = "UPI"
        elif "neft" in event_type.lower():
            transaction_type = "NEFT"
        elif "rtgs" in event_type.lower():
            transaction_type = "RTGS"
        elif "imps" in event_type.lower():
            transaction_type = "IMPS"
        elif "atm" in event_type.lower():
            transaction_type = "ATM"
        elif "card" in event_type.lower():
            transaction_type = "CARD"
            
    txn_status = get_case_insensitive(raw, ["status", "transaction_status", "txn_status", "result"])
    
    # Extract asset metadata
    device_category = device_type
    if not device_category:
        if source_system.lower() in ["core-ledger", "core_banking"]:
            device_category = "Core Banking Server"
        elif "firewall" in source_system.lower() or "waf" in source_system.lower():
            device_category = "Firewall"
            
    network_zone = get_case_insensitive(raw, ["network_zone", "zone"])
    if not network_zone:
        if "dmz" in source_system.lower() or "waf" in source_system.lower():
            network_zone = "DMZ"
        elif "internal" in source_system.lower() or "core" in source_system.lower():
            network_zone = "Internal"
        elif "atm" in event_type.lower() or "branch" in source_system.lower():
            network_zone = "Branch"
        else:
            network_zone = "External"
            
    environment = get_case_insensitive(raw, ["environment", "env"], "Production")
    
    # Extract security fields
    raw_sev = get_case_insensitive(raw, ["severity", "level", "alert_severity"])
    severity = normalize_severity(raw_sev)
    action = get_case_insensitive(raw, ["action", "status_code", "login_status"])
    
    # Build maps
    return {
        "metadata": {
            "event_id": str(event_id),
            "correlation_id": str(correlation_id) if correlation_id is not None else None,
            "session_id": str(session_id) if session_id is not None else None,
            "source_system": str(source_system),
            "event_type": str(event_type),
            "original_timestamp": str(orig_ts) if orig_ts is not None else str(norm_ts),
            "normalized_timestamp": str(norm_ts)
        },
        "identity": {
            "customer_id": str(customer_id) if customer_id is not None else None,
            "employee_id": str(employee_id) if employee_id is not None else None,
            "username": str(username) if username is not None else None,
            "session_id": str(session_id) if session_id is not None else None,
            "device_id": str(device_id) if device_id is not None else None,
            "account_number": str(account_number) if account_number is not None else None,
            "ip_address": str(ip_address) if ip_address is not None else None,
            "beneficiary_id": str(beneficiary_id) if beneficiary_id is not None else None,
            "endpoint_id": str(endpoint_id) if endpoint_id is not None else None
        },
        "network": {
            "source_ip": str(src_ip) if src_ip is not None else None,
            "destination_ip": str(dst_ip) if dst_ip is not None else None,
            "source_port": int(src_port) if src_port is not None and str(src_port).isdigit() else None,
            "destination_port": int(dst_port) if dst_port is not None and str(dst_port).isdigit() else None,
            "protocol": str(protocol).upper() if protocol is not None else None,
            "direction": str(direction) if direction is not None else None,
            "bytes_sent": int(bytes_sent) if bytes_sent is not None and str(bytes_sent).isdigit() else None,
            "bytes_received": int(bytes_received) if bytes_received is not None and str(bytes_received).isdigit() else None
        },
        "device": {
            "device_id": str(device_id) if device_id is not None else None,
            "device_name": str(device_name) if device_name is not None else None,
            "device_type": str(device_type) if device_type is not None else None,
            "os": str(os) if os is not None else None,
            "browser": str(browser) if browser is not None else None
        },
        "transaction": {
            "transaction_id": str(transaction_id) if transaction_id is not None else None,
            "account_number": str(account_number) if account_number is not None else None,
            "amount": amount,
            "currency": str(currency) if currency is not None else None,
            "merchant_name": str(merchant_name) if merchant_name is not None else None,
            "transaction_type": str(transaction_type) if transaction_type is not None else None,
            "beneficiary_id": str(beneficiary_id) if beneficiary_id is not None else None,
            "status": str(txn_status) if txn_status is not None else None
        },
        "asset": {
            "device_category": str(device_category) if device_category is not None else None,
            "network_zone": str(network_zone) if network_zone is not None else None,
            "environment": str(environment) if environment is not None else None
        },
        "security": {
            "severity": str(severity),
            "action": str(action) if action is not None else None
        },
        "threat": {
            "matched": False,
            "indicators": []
        },
        "geo": {
            "country": None,
            "region": None,
            "city": None,
            "asn": None,
            "isp": None,
            "latitude": None,
            "longitude": None,
            "risk_score": 0.0
        },
        "fraud": {
            "high_value_transaction": False,
            "new_beneficiary": False,
            "new_device": False,
            "impossible_travel": False,
            "dormant_account": False,
            "rapid_transaction": False,
            "geo_mismatch": False,
            "velocity_indicator": 0.0
        },
        "mitre": {
            "matched": False,
            "tactic": None,
            "technique": None,
            "technique_id": None,
            "description": None
        },
        "raw_event": raw
    }
