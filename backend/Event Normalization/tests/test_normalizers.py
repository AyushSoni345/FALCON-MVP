import pytest
from app.core.parsers.manager import ParserManager
from app.core.schema import UniversalEventEnvelope

def create_mock_uee(event_type: str, raw_payload: dict, **kwargs) -> dict:
    """Helper factory to build a mock Universal Event Envelope (UEE) dictionary."""
    rp = raw_payload.copy()
    
    # Automatically inject fallback context fields into raw_payload for parser testing
    for field in ["username", "card_number_masked", "user_id", "firewall_device", "public_ip"]:
        if field in kwargs and kwargs[field] is not None:
            rp[field] = kwargs[field]

    return {
        "metadata": {
            "event_uuid": kwargs.get("event_uuid", "mock-uuid-1234"),
            "original_event_id": "orig-id-1",
            "event_type": event_type,
            "event_category": kwargs.get("event_category", "telemetry"),
            "source_system": kwargs.get("source_system", "MockSystem"),
            "source_vendor": kwargs.get("source_vendor", "MockVendor"),
            "ingestion_timestamp": "2026-07-14T11:15:29Z",
            "original_timestamp": "2026-07-14T11:15:29Z",
            "processing_timestamp": "2026-07-14T11:15:29Z",
            "schema_version": "1.0",
            "validation_status": "VALID",
            "duplicate_status": "UNIQUE",
            "processing_status": "PENDING",
            "event_hash": "eventhash123",
            "correlation_id": kwargs.get("correlation_id", "corr-uuid-123"),
            "pipeline_version": "2.0"
        },
        "entity_context": {
            "customer_id": kwargs.get("customer_id"),
            "employee_id": kwargs.get("employee_id"),
            "account_number": kwargs.get("account_number"),
            "transaction_id": kwargs.get("transaction_id"),
            "beneficiary_id": kwargs.get("beneficiary_id"),
            "device_id": kwargs.get("device_id"),
            "endpoint_id": kwargs.get("endpoint_id"),
            "session_id": kwargs.get("session_id"),
            "username": kwargs.get("username"),
            "card_number_masked": kwargs.get("card_number_masked"),
            "user_id": kwargs.get("user_id")
        },
        "network_context": {
            "source_ip": kwargs.get("source_ip"),
            "destination_ip": kwargs.get("destination_ip"),
            "source_port": kwargs.get("source_port"),
            "destination_port": kwargs.get("destination_port"),
            "protocol": kwargs.get("protocol"),
            "country": kwargs.get("country"),
            "city": kwargs.get("city"),
            "public_ip": kwargs.get("public_ip")
        },
        "security_context": {
            "severity": kwargs.get("severity", "info"),
            "action": kwargs.get("action", "allow"),
            "log_source": kwargs.get("log_source", "Mock"),
            "sensor_id": "sensor-1",
            "rule_id": kwargs.get("rule_id"),
            "signature_id": kwargs.get("signature_id"),
            "firewall_device": kwargs.get("firewall_device")
        },
        "raw_payload": rp
    }

def test_parser_manager_selection():
    manager = ParserManager()
    
    fw_parser = manager.get_parser("FIREWALL")
    assert fw_parser is not None
    
    upi_parser = manager.get_parser("upi")
    assert upi_parser is not None
    
    unknown_parser = manager.get_parser("UNKNOWN_LOG_TYPE")
    assert unknown_parser is None

def test_firewall_parser():
    raw_payload = {
        "SRC_IP": "192.168.1.5",
        "DST_IP": "10.0.1.50",
        "SOURCE_PORT": "54321",
        "DESTINATION_PORT": "443",
        "PROTOCOL": "TCP",
        "ACTION": "BLOCK",
        "RULE_ID": "fw-rule-100",
        "BYTES_SENT": "1024",
        "BYTES_RECEIVED": "512"
    }
    
    uee_dict = create_mock_uee("FIREWALL", raw_payload, source_ip="192.168.1.5", severity="high", action="block")
    uee = UniversalEventEnvelope.model_validate(uee_dict)
    
    manager = ParserManager()
    parser = manager.get_parser("FIREWALL")
    
    parsed = parser.normalize(uee)
    assert parsed["network_context"]["source_ip"] == "192.168.1.5"
    assert parsed["network_context"]["destination_ip"] == "10.0.1.50"
    assert parsed["network_context"]["destination_port"] == 443
    assert parsed["security_context"]["action"] == "BLOCK"
    assert parsed["security_context"]["severity"] == "HIGH"
    assert parsed["normalized_event_data"]["bytes_sent"] == 1024

def test_vpn_parser():
    raw_payload = {
        "Client_IP": "8.8.8.8",
        "VPN Gateway": "gateway-asia-1",
        "Authentication": "SUCCESS",
        "MFA": "DUO_PUSH",
        "DeviceID": "DEV-CORP-01"
    }
    
    uee_dict = create_mock_uee("VPN", raw_payload, username="alice_emp", device_id="DEV-CORP-01")
    uee = UniversalEventEnvelope.model_validate(uee_dict)
    
    parser = ParserManager().get_parser("VPN")
    parsed = parser.normalize(uee)
    
    assert parsed["identity_context"]["username"] == "alice_emp"
    assert parsed["identity_context"]["ip_address"] == "8.8.8.8"
    assert parsed["asset_context"]["device_type"] == "VPN Gateway"
    assert parsed["asset_context"]["vpn_gateway"] == "gateway-asia-1"
    assert parsed["identity_context"]["mfa_status"] == "DUO_PUSH"

def test_uee_context_fields_propagation():
    """Verifies that username, user_id, card_number_masked, public_ip, and firewall_device parse and propagate correctly."""
    raw_payload = {}
    uee_dict = create_mock_uee(
        "FIREWALL", 
        raw_payload, 
        username="test_user", 
        user_id="usr-123",
        card_number_masked="1234XXXXXXXX5678", 
        public_ip="8.8.8.8", 
        firewall_device="FW_DEV_99"
    )
    uee = UniversalEventEnvelope.model_validate(uee_dict)
    
    # Assert they are parsed correctly by Pydantic on the model contexts
    assert uee.entity_context.username == "test_user"
    assert uee.entity_context.user_id == "usr-123"
    assert uee.entity_context.card_number_masked == "1234XXXXXXXX5678"
    assert uee.network_context.public_ip == "8.8.8.8"
    assert uee.security_context.firewall_device == "FW_DEV_99"

