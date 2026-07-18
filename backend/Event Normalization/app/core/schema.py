from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List

# ==========================================
# PART 1: MODULE 1 INPUT CONTRACT (UEE)
# ==========================================

class UniversalEventMetadata(BaseModel):
    event_uuid: str
    original_event_id: Optional[str] = None
    event_type: str
    event_category: Optional[str] = None
    source_system: str
    source_vendor: Optional[str] = None
    ingestion_timestamp: str
    original_timestamp: str
    processing_timestamp: str
    validation_status: str
    duplicate_status: str
    schema_version: str
    event_hash: str
    correlation_id: str
    pipeline_version: str
    processing_status: str

class UniversalEntityContext(BaseModel):
    customer_id: Optional[str] = None
    employee_id: Optional[str] = None
    account_number: Optional[str] = None
    transaction_id: Optional[str] = None
    session_id: Optional[str] = None
    device_id: Optional[str] = None
    endpoint_id: Optional[str] = None
    beneficiary_id: Optional[str] = None

    username: Optional[str] = None
    card_number_masked: Optional[str] = None
    user_id: Optional[str] = None

class UniversalNetworkContext(BaseModel):
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    public_ip: Optional[str] = None

class UniversalSecurityContext(BaseModel):
    severity: Optional[str] = None
    action: Optional[str] = None
    rule_id: Optional[str] = None
    sensor_id: Optional[str] = None
    signature_id: Optional[str] = None
    log_source: Optional[str] = None
    firewall_device: Optional[str] = None

class UniversalEventEnvelope(BaseModel):
    metadata: UniversalEventMetadata
    entity_context: UniversalEntityContext
    network_context: UniversalNetworkContext
    security_context: UniversalSecurityContext
    raw_payload: Dict[str, Any]

# ==========================================
# PART 2: MODULE 2 OUTPUT CONTRACT (CEE)
# ==========================================

class EventInformation(BaseModel):
    event_uuid: str
    original_event_id: Optional[str] = None
    event_type: str
    event_category: Optional[str] = None
    source_system: str
    source_vendor: Optional[str] = None
    normalized_timestamp: str
    original_timestamp: str
    ingestion_timestamp: str
    processing_timestamp: str
    correlation_id: str
    batch_id: Optional[str] = None
    stream_id: Optional[str] = None
    schema_version: str
    pipeline_version: str
    processing_status: str
    processing_duration_ms: float

class IdentityContext(BaseModel):
    customer_id: Optional[str] = None
    employee_id: Optional[str] = None
    user_id: Optional[str] = None
    username: Optional[str] = None
    account_number: Optional[str] = None
    card_number_masked: Optional[str] = None
    customer_type: Optional[str] = None
    role: Optional[str] = None
    department: Optional[str] = None
    authentication_method: Optional[str] = None
    authentication_status: Optional[str] = None
    mfa_status: Optional[str] = None

class AssetContext(BaseModel):
    device_id: Optional[str] = None
    endpoint_id: Optional[str] = None
    device_type: Optional[str] = None
    operating_system: Optional[str] = None
    browser: Optional[str] = None
    firewall: Optional[str] = None
    vpn_gateway: Optional[str] = None
    atm_id: Optional[str] = None
    pos_terminal: Optional[str] = None
    server_id: Optional[str] = None
    asset_name: Optional[str] = None
    asset_group: Optional[str] = None
    asset_location: Optional[str] = None
    asset_owner: Optional[str] = None
    asset_criticality: Optional[str] = None

class NetworkContext(BaseModel):
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    public_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    region: Optional[str] = None
    network_zone: Optional[str] = None
    vpn_used: bool = False
    proxy_used: bool = False
    asn: Optional[str] = None
    isp: Optional[str] = None
    connection_type: Optional[str] = None

class FinancialContext(BaseModel):
    transaction_id: Optional[str] = None
    transaction_type: Optional[str] = None
    payment_channel: Optional[str] = None
    amount: Optional[float] = None
    currency: Optional[str] = None
    sender_account: Optional[str] = None
    receiver_account: Optional[str] = None
    beneficiary_id: Optional[str] = None
    receiver_bank: Optional[str] = None
    merchant: Optional[str] = None
    merchant_category: Optional[str] = None
    branch: Optional[str] = None
    transaction_status: Optional[str] = None
    account_balance: Optional[float] = None
    approval_code: Optional[str] = None
    ifsc: Optional[str] = None

class SecurityContext(BaseModel):
    severity: Optional[str] = None
    action: Optional[str] = None
    attack_name: Optional[str] = None
    signature: Optional[str] = None
    signature_id: Optional[str] = None
    rule_name: Optional[str] = None
    rule_id: Optional[str] = None
    sensor_id: Optional[str] = None
    log_source: Optional[str] = None
    malware_name: Optional[str] = None
    process_name: Optional[str] = None
    process_hash: Optional[str] = None
    detection_status: Optional[str] = None
    encryption_status: Optional[str] = None
    cpu_usage: Optional[float] = None
    memory_usage: Optional[float] = None

class ThreatContext(BaseModel):
    IOC_match: bool = False
    IOC_value: Optional[str] = None
    IOC_type: Optional[str] = None
    IOC_confidence: float = 0.0
    malicious_ip: Optional[str] = None
    malicious_domain: Optional[str] = None
    malicious_hash: Optional[str] = None
    threat_actor: Optional[str] = None
    malware_family: Optional[str] = None
    ATTACK_campaign: Optional[str] = None
    MITRE_tactic: Optional[str] = None
    MITRE_technique: Optional[str] = None
    MITRE_technique_id: Optional[str] = None
    C2_server: Optional[str] = None
    reputation_score: float = 0.0
    intel_source: Optional[str] = None
    intel_timestamp: Optional[str] = None

class FraudContext(BaseModel):
    high_risk_beneficiary: bool = False
    mule_account: bool = False
    blacklisted_account: bool = False
    high_risk_country: bool = False
    risky_merchant: bool = False
    first_time_payee: bool = False
    rapid_beneficiary_addition: bool = False
    unusual_transaction_pattern: bool = False
    velocity_indicator: float = 0.0
    large_transfer: bool = False
    new_payee: bool = False
    new_merchant: bool = False

class GeoContext(BaseModel):
    country: Optional[str] = None
    city: Optional[str] = None
    region: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    timezone: Optional[str] = None
    asn: Optional[str] = None
    isp: Optional[str] = None
    geo_source: Optional[str] = None
    lookup_timestamp: Optional[str] = None

class BehavioralFeatures(BaseModel):
    new_device: bool = False
    new_location: bool = False
    first_login_today: bool = False
    unusual_login_hour: bool = False
    multiple_failed_logins: bool = False
    high_transaction_amount: bool = False
    repeated_transactions: bool = False
    foreign_transaction: bool = False
    multiple_atm_usage: bool = False
    new_browser: bool = False
    new_operating_system: bool = False
    abnormal_cpu_usage: bool = False
    abnormal_memory_usage: bool = False
    large_archive_access: bool = False
    bulk_encrypted_transfer: bool = False
    possible_impossible_travel: bool = False
    new_beneficiary: bool = False
    new_ip: bool = False
    new_network: bool = False

class RelationshipContext(BaseModel):
    customer_id: Optional[str] = None
    employee_id: Optional[str] = None
    session_id: Optional[str] = None
    device_id: Optional[str] = None
    endpoint_id: Optional[str] = None
    beneficiary_id: Optional[str] = None
    transaction_id: Optional[str] = None
    parent_event: Optional[str] = None
    linked_events: List[str] = Field(default_factory=list)
    relationship_keys: Dict[str, str] = Field(default_factory=dict)
    identity_chain: List[str] = Field(default_factory=list)
    asset_chain: List[str] = Field(default_factory=list)
    transaction_chain: List[str] = Field(default_factory=list)

class ContextEnrichedEvent(BaseModel):
    event_information: EventInformation
    identity_context: IdentityContext
    asset_context: AssetContext
    network_context: NetworkContext
    financial_context: FinancialContext
    security_context: SecurityContext
    threat_context: ThreatContext
    fraud_context: FraudContext
    geo_context: GeoContext
    behavioral_features: BehavioralFeatures
    relationship_context: RelationshipContext
    normalized_event_data: Dict[str, Any]
