from pydantic import BaseModel, Field
from typing import Optional, Dict, Any

class CommonEnvelope(BaseModel):
    event_id: str = Field(description="Unique Event ID (UUID)")
    event_type: str = Field(description="Type of the event, matching one of the 15 categories")
    source_system: str = Field(description="System that generated the event")
    timestamp: str = Field(description="UTC timestamp in ISO-8601 format (YYYY-MM-DDTHH:MM:SSZ)")
    severity: str = Field(description="Severity levels: INFO, LOW, MEDIUM, HIGH, CRITICAL")
    correlation_id: Optional[str] = Field(default=None, description="Shared ID linking events in an attack chain or session")
    customer_id: Optional[str] = Field(default=None, description="Customer ID if applicable")
    employee_id: Optional[str] = Field(default=None, description="Employee ID if applicable")
    device_id: Optional[str] = Field(default=None, description="Device ID if applicable")
    session_id: Optional[str] = Field(default=None, description="Session ID if applicable")
    ip_address: Optional[str] = Field(default=None, description="IP Address if applicable")
    raw_payload: Dict[str, Any] = Field(description="Source-specific key-value pairs")

class FirewallPayload(BaseModel):
    firewall_device_id: str
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    action: str
    rule_id: str
    interface: str
    bytes_sent: int
    bytes_received: int
    session_id: Optional[str] = None

class IDSPayload(BaseModel):
    sensor_id: str
    source_ip: str
    destination_ip: str
    signature_id: str
    attack_name: str
    severity: str
    confidence: float
    protocol: str
    action: str
    mitre_technique: Optional[str] = None

class VPNPayload(BaseModel):
    session_id: str
    user_id: str
    employee_id: Optional[str] = None
    vpn_gateway: str
    source_ip: str
    country: str
    device_id: str
    login_time: str
    logout_time: Optional[str] = None
    mfa_status: str
    authentication_status: str

class IAMPayload(BaseModel):
    user_id: str
    username: str
    user_type: str
    login_status: str
    authentication_method: str
    mfa_result: str
    device_id: str
    ip_address: str
    session_id: str
    failure_reason: Optional[str] = None

class InternetBankingPayload(BaseModel):
    customer_id: str
    account_number: str
    device_id: str
    browser: str
    operating_system: str
    ip_address: str
    gps_location: str
    login_status: str
    session_id: str

class CoreBankingPayload(BaseModel):
    transaction_id: str
    account_number: str
    customer_id: str
    transaction_type: str
    amount: float
    currency: str
    balance_before: float
    balance_after: float
    branch: str
    channel: str
    status: str

class UPIPayload(BaseModel):
    transaction_id: str
    upi_id: str
    customer_id: str
    sender_account: str
    receiver_upi: str
    receiver_bank: str
    amount: float
    device_id: str
    ip_address: str
    merchant: Optional[str] = None
    status: str

class NEFTPayload(BaseModel):
    transaction_id: str
    account_number: str
    beneficiary_account: str
    beneficiary_bank: str
    ifsc: str
    amount: float
    channel: str
    transaction_status: str

class CardPayload(BaseModel):
    transaction_id: str
    masked_card_number: str
    merchant_id: str
    merchant_category: str
    pos_terminal: str
    country: str
    city: str
    amount: float
    currency: str
    approval_code: Optional[str] = None

class ATMPayload(BaseModel):
    atm_id: str
    transaction_id: str
    card_number: str
    customer_id: str
    transaction_type: str
    amount: float
    balance: float
    atm_location: str
    status: str

class BeneficiaryPayload(BaseModel):
    customer_id: str
    beneficiary_id: str
    beneficiary_name: str
    account_number: str
    ifsc: str
    action: str

class EndpointPayload(BaseModel):
    endpoint_id: str
    device_id: str
    user: str
    process_name: str
    process_hash: str
    malware_name: Optional[str] = None
    detection_status: str
    cpu_usage: float
    memory_usage: float

class SIEMPayload(BaseModel):
    correlation_id: Optional[str] = None
    source_system: str
    severity: str
    event_category: str
    rule_name: str

class ThreatIntelPayload(BaseModel):
    ioc_id: str
    ioc_type: str
    ioc_value: str
    threat_actor: str
    malware_family: str
    confidence_score: float
    first_seen: str
    last_seen: str
    mitre_attack_mapping: str

class QuantumPayload(BaseModel):
    server_id: str
    archive_id: str
    encryption_algorithm: str
    data_volume: str
    read_duration: int
    outbound_destination: str
    transfer_size: str
    encryption_status: str

# Dictionary mapping event types to their specific Pydantic payload models
PAYLOAD_MODELS = {
    "firewall": FirewallPayload,
    "ids_ips": IDSPayload,
    "vpn": VPNPayload,
    "iam": IAMPayload,
    "internet_banking": InternetBankingPayload,
    "core_banking": CoreBankingPayload,
    "upi": UPIPayload,
    "neft_rtgs_imps": NEFTPayload,
    "card": CardPayload,
    "atm": ATMPayload,
    "beneficiary": BeneficiaryPayload,
    "endpoint": EndpointPayload,
    "siem": SIEMPayload,
    "threat_intel": ThreatIntelPayload,
    "quantum_hndl": QuantumPayload
}

class UEE_Metadata(BaseModel):
    event_uuid: str
    original_event_id: str
    event_type: str
    event_category: str
    source_system: str
    source_vendor: str
    ingestion_timestamp: str
    original_timestamp: str
    processing_timestamp: str
    validation_status: str
    validation_errors: Optional[str] = None
    duplicate_status: str
    duplicate_reference: Optional[str] = None
    processing_status: str
    schema_version: str = "1.0.0"
    pipeline_version: str = "1.0.0"
    event_hash: str
    correlation_id: Optional[str] = None
    batch_id: Optional[str] = None
    stream_id: Optional[str] = None
    event_size: int
    event_priority: str

class UEE_EntityContext(BaseModel):
    customer_id: Optional[str] = None
    employee_id: Optional[str] = None
    username: Optional[str] = None
    account_number: Optional[str] = None
    card_number_masked: Optional[str] = None
    transaction_id: Optional[str] = None
    beneficiary_id: Optional[str] = None
    device_id: Optional[str] = None
    endpoint_id: Optional[str] = None
    session_id: Optional[str] = None
    user_id: Optional[str] = None

class UEE_NetworkContext(BaseModel):
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    public_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None

class UEE_SecurityContext(BaseModel):
    severity: Optional[str] = None
    action: Optional[str] = None
    log_source: Optional[str] = None
    sensor_id: Optional[str] = None
    firewall_device: Optional[str] = None
    rule_id: Optional[str] = None
    signature_id: Optional[str] = None

class UniversalEventEnvelope(BaseModel):
    metadata: UEE_Metadata
    entity_context: UEE_EntityContext
    network_context: UEE_NetworkContext
    security_context: UEE_SecurityContext
    raw_payload: Dict[str, Any]
