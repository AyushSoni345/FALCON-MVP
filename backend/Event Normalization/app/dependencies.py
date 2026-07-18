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

_repo = InMemoryStateRepository()
_parser_manager = ParserManager()
_resolver = IdentityResolver()
_geo_service = GeoService()
_threat_intel = ThreatIntelEnricher()
_mitre_mapper = MitreMapper()
_fraud_engine = FraudContextEngine(_repo)
_behavior_engine = BehavioralFeatureEngine(_repo)
_relationship_engine = RelationshipContextEngine()

_engine = NormalizationEnrichmentEngine(
    repo=_repo,
    parser_manager=_parser_manager,
    resolver=_resolver,
    geo_service=_geo_service,
    threat_intel=_threat_intel,
    mitre_mapper=_mitre_mapper,
    fraud_engine=_fraud_engine,
    behavior_engine=_behavior_engine,
    relationship_engine=_relationship_engine
)

def get_repository() -> InMemoryStateRepository:
    return _repo

def get_engine() -> NormalizationEnrichmentEngine:
    return _engine
