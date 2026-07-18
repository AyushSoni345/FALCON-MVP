import pytest
from app.core.enrichment.geo import GeoService
from app.core.enrichment.threat_intel import ThreatIntelEnricher
from app.core.enrichment.mitre import MitreMapper
from app.core.enrichment.fraud import FraudContextEngine
from app.core.enrichment.behavior import BehavioralFeatureEngine
from app.core.enrichment.relationship import RelationshipContextEngine
from app.database.memory_repo import InMemoryStateRepository

def test_geo_enrichment():
    geo_service = GeoService()
    
    event = {
        "event_information": {"normalized_timestamp": "2026-07-14T11:15:29Z"},
        "identity_context": {"ip_address": "192.168.1.100"},
        "network_context": {},
        "geo_context": {}
    }
    geo_service.enrich(event)
    assert event["geo_context"]["country"] == "Internal Network"
    assert event["geo_context"]["geo_source"] == "PrivateIP"

    event2 = {
        "event_information": {"normalized_timestamp": "2026-07-14T11:15:29Z"},
        "identity_context": {"ip_address": "8.8.8.8"},
        "network_context": {},
        "geo_context": {}
    }
    geo_service.enrich(event2)
    assert event2["geo_context"]["country"] == "United States"
    assert event2["geo_context"]["geo_source"] == "IP_Database"

def test_threat_intel_enricher():
    ti = ThreatIntelEnricher()
    
    event = {
        "event_information": {"event_type": "Firewall"},
        "identity_context": {"ip_address": "45.9.148.15"},
        "network_context": {"source_ip": "45.9.148.15"},
        "security_context": {"severity": "LOW"},
        "threat_context": {}
    }
    ti.enrich(event)
    assert event["threat_context"]["IOC_match"] is True
    assert event["threat_context"]["threat_actor"] == "Wizard Spider"
    assert event["security_context"]["severity"] == "HIGH"

def test_mitre_mapper():
    mapper = MitreMapper()
    
    event = {
        "event_information": {"event_type": "Quantum Event", "source_system": "QuantumSensors"},
        "security_context": {"severity": "LOW"},
        "threat_context": {},
        "raw_payload": {"anomaly_type": "HNDL_suspected"}
    }
    mapper.enrich(event)
    assert event["threat_context"]["MITRE_tactic"] == "Exfiltration"
    assert event["threat_context"]["MITRE_technique_id"] == "T1048"

@pytest.mark.asyncio
async def test_stateful_fraud_and_behavioral_engines():
    repo = InMemoryStateRepository()
    fraud_engine = FraudContextEngine(repo)
    behavior_engine = BehavioralFeatureEngine(repo)
    relationship_engine = RelationshipContextEngine()

    event = {
        "event_information": {
            "event_type": "UPI",
            "normalized_timestamp": "2026-07-14T11:15:00Z",
            "correlation_id": "corr-1"
        },
        "identity_context": {
            "customer_id": "CUST-A",
            "account_number": "ACC-9911",
            "device_id": "DEV-IPHONE",
            "beneficiary_id": "BEN-BOB",
            "username": "alice_user"
        },
        "asset_context": {
            "browser": "Safari Mobile",
            "operating_system": "iOS"
        },
        "geo_context": {
            "latitude": 12.97,
            "longitude": 77.59,
            "country": "India"
        },
        "financial_context": {
            "amount": 600000.0,
            "beneficiary_id": "BEN-BOB",
            "transaction_id": "TXN-901"
        },
        "security_context": {
            "severity": "LOW",
            "action": "ALLOW"
        },
        "threat_context": {},
        "fraud_context": {},
        "behavioral_features": {},
        "relationship_context": {}
    }

    await fraud_engine.enrich_async(event)
    assert event["fraud_context"]["large_transfer"] is True
    assert event["fraud_context"]["first_time_payee"] is True

    await behavior_engine.enrich_async(event)
    assert event["behavioral_features"]["new_device"] is True
    assert event["behavioral_features"]["new_browser"] is True
    assert event["behavioral_features"]["first_login_today"] is True
    assert event["behavioral_features"]["high_transaction_amount"] is True

    relationship_engine.enrich(event)
    assert event["relationship_context"]["customer_id"] == "CUST-A"
    assert "customer_account" in event["relationship_context"]["relationship_keys"]
    assert event["relationship_context"]["relationship_keys"]["customer_account"] == "CUST-A:::ACC-9911"
