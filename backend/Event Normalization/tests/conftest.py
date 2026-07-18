import pytest
import asyncio
from typing import AsyncGenerator
from fastapi.testclient import TestClient
from app.main import app
from app.database.memory_repo import InMemoryStateRepository
from app.core.resolver import IdentityResolver
from app.core.enrichment.geo import GeoService
from app.core.enrichment.threat_intel import ThreatIntelEnricher
from app.core.enrichment.mitre import MitreMapper
from app.core.enrichment.fraud import FraudContextEngine
from app.core.enrichment.behavior import BehavioralFeatureEngine
from app.core.enrichment.relationship import RelationshipContextEngine
from app.core.parsers.manager import ParserManager
from app.core.engine import NormalizationEnrichmentEngine
from app.dependencies import get_engine, get_repository

@pytest.fixture(scope="session")
def event_loop():
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
    yield loop
    loop.close()

@pytest.fixture
def test_repo() -> InMemoryStateRepository:
    return InMemoryStateRepository()

@pytest.fixture
def test_engine(test_repo) -> NormalizationEnrichmentEngine:
    parser_manager = ParserManager()
    resolver = IdentityResolver()
    geo_service = GeoService()
    threat_intel = ThreatIntelEnricher()
    mitre_mapper = MitreMapper()
    fraud_engine = FraudContextEngine(test_repo)
    behavior_engine = BehavioralFeatureEngine(test_repo)
    relationship_engine = RelationshipContextEngine()
    
    return NormalizationEnrichmentEngine(
        repo=test_repo,
        parser_manager=parser_manager,
        resolver=resolver,
        geo_service=geo_service,
        threat_intel=threat_intel,
        mitre_mapper=mitre_mapper,
        fraud_engine=fraud_engine,
        behavior_engine=behavior_engine,
        relationship_engine=relationship_engine
    )

@pytest.fixture
def client(test_repo, test_engine) -> TestClient:
    app.dependency_overrides[get_repository] = lambda: test_repo
    app.dependency_overrides[get_engine] = lambda: test_engine
    
    with TestClient(app) as test_client:
        yield test_client
        
    app.dependency_overrides.clear()
