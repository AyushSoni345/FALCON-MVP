import time
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from app.core.schema import UniversalEventEnvelope, ContextEnrichedEvent
from app.core.parsers.manager import ParserManager
from app.core.resolver import IdentityResolver
from app.core.enrichment.geo import GeoService
from app.core.enrichment.threat_intel import ThreatIntelEnricher
from app.core.enrichment.mitre import MitreMapper
from app.core.enrichment.fraud import FraudContextEngine
from app.core.enrichment.behavior import BehavioralFeatureEngine
from app.core.enrichment.relationship import RelationshipContextEngine
from app.database.repository import StateRepository
from app.logging_config import log_pipeline

class PipelineError(Exception):
    """Custom Exception thrown when a pipeline validation, parser, or coding failure occurs."""
    def __init__(
        self,
        error_code: str,
        error_message: str,
        processing_stage: str,
        event_uuid: Optional[str] = None,
        recommended_action: str = ""
    ):
        super().__init__(error_message)
        self.error_code = error_code
        self.error_message = error_message
        self.processing_stage = processing_stage
        self.event_uuid = event_uuid
        self.recommended_action = recommended_action

class NormalizationEnrichmentEngine:
    """
    Orchestration pipeline for FALCON Module 2.
    Converts Universal Event Envelopes (UEE) to Context Enriched Events (CEE).
    """

    def __init__(
        self,
        repo: StateRepository,
        parser_manager: ParserManager,
        resolver: IdentityResolver,
        geo_service: GeoService,
        threat_intel: ThreatIntelEnricher,
        mitre_mapper: MitreMapper,
        fraud_engine: FraudContextEngine,
        behavior_engine: BehavioralFeatureEngine,
        relationship_engine: RelationshipContextEngine
    ):
        self.repo = repo
        self.parser_manager = parser_manager
        self.resolver = resolver
        self.geo_service = geo_service
        self.threat_intel = threat_intel
        self.mitre_mapper = mitre_mapper
        self.fraud_engine = fraud_engine
        self.behavior_engine = behavior_engine
        self.relationship_engine = relationship_engine

    async def process_event(self, uee_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Orchestrates full normalization and enrichment pipeline for a single event envelope.
        """
        start_time = time.perf_counter()
        
        # 1. Parse and Validate Universal Event Envelope
        event_uuid = uee_data.get("metadata", {}).get("event_uuid")
        corr_id = uee_data.get("metadata", {}).get("correlation_id")
        
        log_pipeline(
            logging.INFO, "Request Received", "request_received", "started",
            event_uuid=event_uuid, correlation_id=corr_id
        )

        try:
            uee = UniversalEventEnvelope.model_validate(uee_data)
            log_pipeline(
                logging.INFO, "Envelope Validated", "envelope_validation", "success",
                event_uuid=uee.metadata.event_uuid, correlation_id=uee.metadata.correlation_id
            )
        except Exception as e:
            log_pipeline(
                logging.ERROR, f"Envelope validation failed: {e}", "envelope_validation", "failed",
                event_uuid=event_uuid, correlation_id=corr_id
            )
            raise PipelineError(
                error_code="INVALID_ENVELOPE",
                error_message=f"Universal Event Envelope validation failed: {str(e)}",
                processing_stage="envelope_validation",
                event_uuid=event_uuid,
                recommended_action="Ensure the input request conforms strictly to the Universal Event Envelope schema."
            )

        meta = uee.metadata
        event_uuid = meta.event_uuid
        corr_id = meta.correlation_id
        event_type = meta.event_type.upper().strip()
        
        log_pipeline(
            logging.INFO, f"Event Type = {event_type}", "event_type_detected", "success",
            event_uuid=event_uuid, correlation_id=corr_id
        )

        # 2. Select appropriate parser based on event_type
        parser = self.parser_manager.get_parser(event_type)
        if not parser:
            error_msg = f"No supported parser found for event type: {event_type}"
            log_pipeline(
                logging.ERROR, error_msg, "parser_selection", "failed",
                event_uuid=event_uuid, correlation_id=corr_id
            )
            cee_dict = self._create_error_cee(uee, "parser_selection", error_msg, start_time)
            await self.repo.save_normalized_event(event_uuid, cee_dict)
            raise PipelineError(
                error_code="UNSUPPORTED_EVENT_TYPE",
                error_message=error_msg,
                processing_stage="parser_selection",
                event_uuid=event_uuid,
                recommended_action="Check if the metadata.event_type field matches one of the 17 supported event types."
            )

        parser_name = parser.__class__.__name__
        log_pipeline(
            logging.INFO, f"Selected Parser = {parser_name}", "parser_selected", "success",
            event_uuid=event_uuid, correlation_id=corr_id, parser_name=parser_name
        )

        # Validate UEE against parser rules (Logged at DEBUG level to avoid cluttering terminal)
        if not parser.validate(uee):
            warning_msg = f"Parser validation warning for event type: {event_type}. Telemetry fields missing."
            log_pipeline(
                logging.DEBUG, warning_msg, "normalization_check", "warning",
                event_uuid=event_uuid, correlation_id=corr_id, parser_name=parser_name
            )

        # 3. Normalize fields using selected Parser
        log_pipeline(
            logging.INFO, "Normalization Started", "normalization", "started",
            event_uuid=event_uuid, correlation_id=corr_id, parser_name=parser_name
        )
        norm_start = time.perf_counter()
        try:
            parsed = parser.normalize(uee)
            norm_dur = (time.perf_counter() - norm_start) * 1000.0
            
            cee_dict = self._create_base_cee(uee, parsed, start_time)
            log_pipeline(
                logging.INFO, "Normalization Completed", "normalization", "success",
                event_uuid=event_uuid, correlation_id=corr_id, duration=norm_dur, parser_name=parser_name
            )
        except Exception as e:
            error_msg = f"Normalization failure inside parser {parser_name}: {str(e)}"
            log_pipeline(
                logging.ERROR, error_msg, "normalization", "failed",
                event_uuid=event_uuid, correlation_id=corr_id, parser_name=parser_name
            )
            cee_dict = self._create_error_cee(uee, "normalization", error_msg, start_time)
            await self.repo.save_normalized_event(event_uuid, cee_dict)
            raise PipelineError(
                error_code="NORMALIZATION_FAILURE",
                error_message=error_msg,
                processing_stage="normalization",
                event_uuid=event_uuid,
                recommended_action="Ensure the raw_payload contains all required parameters for the specified event type."
            )

        # 4. Identity Resolution
        id_start = time.perf_counter()
        try:
            cee_dict = self.resolver.resolve(uee, cee_dict)
            id_dur = (time.perf_counter() - id_start) * 1000.0
            log_pipeline(
                logging.INFO, "Identity Resolution Completed", "identity_resolution", "success",
                event_uuid=event_uuid, correlation_id=corr_id, duration=id_dur, parser_name=parser_name
            )
        except Exception as e:
            error_msg = f"Identity resolution failed: {e}"
            log_pipeline(
                logging.WARNING, error_msg, "identity_resolution", "warning",
                event_uuid=event_uuid, correlation_id=corr_id, parser_name=parser_name
            )

        # 5. Geographic Intelligence Enrichment
        geo_start = time.perf_counter()
        try:
            cee_dict = self.geo_service.enrich(cee_dict)
            geo_dur = (time.perf_counter() - geo_start) * 1000.0
            log_pipeline(
                logging.INFO, "Geo Enrichment Completed", "geo_enrichment", "success",
                event_uuid=event_uuid, correlation_id=corr_id, duration=geo_dur, parser_name=parser_name
            )
        except Exception as e:
            error_msg = f"Geographic enrichment failed: {e}"
            log_pipeline(
                logging.WARNING, error_msg, "geo_enrichment", "warning",
                event_uuid=event_uuid, correlation_id=corr_id, parser_name=parser_name
            )

        # 6. Threat Intelligence Enrichment
        ti_start = time.perf_counter()
        try:
            cee_dict = self.threat_intel.enrich(cee_dict)
            ti_dur = (time.perf_counter() - ti_start) * 1000.0
            log_pipeline(
                logging.INFO, "Threat Intelligence Completed", "threat_enrichment", "success",
                event_uuid=event_uuid, correlation_id=corr_id, duration=ti_dur, parser_name=parser_name
            )
        except Exception as e:
            error_msg = f"Threat intelligence lookup failed: {e}"
            log_pipeline(
                logging.WARNING, error_msg, "threat_enrichment", "warning",
                event_uuid=event_uuid, correlation_id=corr_id, parser_name=parser_name
            )

        # 7. Stateful Fraud Enrichment
        fraud_start = time.perf_counter()
        try:
            cee_dict = await self.fraud_engine.enrich_async(cee_dict)
            fraud_dur = (time.perf_counter() - fraud_start) * 1000.0
            log_pipeline(
                logging.INFO, "Fraud Feature Generation Completed", "fraud_enrichment", "success",
                event_uuid=event_uuid, correlation_id=corr_id, duration=fraud_dur, parser_name=parser_name
            )
        except Exception as e:
            error_msg = f"Fraud enrichment failed: {e}"
            log_pipeline(
                logging.WARNING, error_msg, "fraud_enrichment", "warning",
                event_uuid=event_uuid, correlation_id=corr_id, parser_name=parser_name
            )

        # 8. MITRE ATT&CK Mapping (Logged at DEBUG to keep terminal sequence exactly clean)
        try:
            cee_dict = self.mitre_mapper.enrich(cee_dict)
        except Exception as e:
            log_pipeline(
                logging.DEBUG, f"MITRE mapping error: {e}", "mitre_mapping", "warning",
                event_uuid=event_uuid, correlation_id=corr_id, parser_name=parser_name
            )

        # 9. Behavioral Feature Enrichment
        behav_start = time.perf_counter()
        try:
            cee_dict = await self.behavior_engine.enrich_async(cee_dict)
            behav_dur = (time.perf_counter() - behav_start) * 1000.0
            log_pipeline(
                logging.INFO, "Behavior Features Completed", "behavioral_features", "success",
                event_uuid=event_uuid, correlation_id=corr_id, duration=behav_dur, parser_name=parser_name
            )
        except Exception as e:
            error_msg = f"Behavioral feature extraction failed: {e}"
            log_pipeline(
                logging.WARNING, error_msg, "behavioral_features", "warning",
                event_uuid=event_uuid, correlation_id=corr_id, parser_name=parser_name
            )

        # 10. Graph Relationship Context Generation
        rel_start = time.perf_counter()
        try:
            cee_dict = self.relationship_engine.enrich(cee_dict)
            rel_dur = (time.perf_counter() - rel_start) * 1000.0
            log_pipeline(
                logging.INFO, "Relationship Context Completed", "relationship_context", "success",
                event_uuid=event_uuid, correlation_id=corr_id, duration=rel_dur, parser_name=parser_name
            )
        except Exception as e:
            error_msg = f"Relationship context generation failed: {e}"
            log_pipeline(
                logging.WARNING, error_msg, "relationship_context", "warning",
                event_uuid=event_uuid, correlation_id=corr_id, parser_name=parser_name
            )

        # Set final execution metrics
        cee_dict["event_information"]["processing_status"] = "SUCCESS"
        
        duration = (time.perf_counter() - start_time) * 1000.0
        cee_dict["event_information"]["processing_duration_ms"] = duration

        # 11. Validate Response structure (CEE)
        try:
            validated_event = ContextEnrichedEvent.model_validate(cee_dict)
            validated_dict = validated_event.model_dump()
            log_pipeline(
                logging.INFO, "Context Enriched Event Generated", "cee_generation", "success",
                event_uuid=event_uuid, correlation_id=corr_id, parser_name=parser_name
            )
        except Exception as e:
            error_msg = f"ContextEnrichedEvent schema validation failed: {e}"
            log_pipeline(
                logging.ERROR, error_msg, "cee_validation", "failed",
                event_uuid=event_uuid, correlation_id=corr_id, parser_name=parser_name
            )
            raise PipelineError(
                error_code="VALIDATION_ERROR",
                error_message=error_msg,
                processing_stage="cee_validation",
                event_uuid=event_uuid,
                recommended_action="Verify pipeline output conforms to Context Enriched Event requirements."
            )

        # 12. Save to repository (Logged at DEBUG to keep terminal access output clean)
        log_pipeline(
            logging.DEBUG, "Saving event payload to database repository.", "repository_save", "started",
            event_uuid=event_uuid, correlation_id=corr_id, parser_name=parser_name
        )
        await self.repo.save_normalized_event(event_uuid, validated_dict)
        log_pipeline(
            logging.DEBUG, "Event stored in database.", "repository_save", "success",
            event_uuid=event_uuid, correlation_id=corr_id, parser_name=parser_name
        )

        return validated_dict

    def _create_base_cee(self, uee: UniversalEventEnvelope, parsed: Dict[str, Any], start_time: float) -> Dict[str, Any]:
        meta = uee.metadata
        current_time_str = datetime.utcnow().replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        
        return {
            "event_information": {
                "event_uuid": meta.event_uuid,
                "original_event_id": meta.original_event_id,
                "event_type": meta.event_type,
                "event_category": meta.event_category,
                "source_system": meta.source_system,
                "source_vendor": meta.source_vendor,
                "normalized_timestamp": current_time_str,
                "original_timestamp": meta.original_timestamp,
                "ingestion_timestamp": meta.ingestion_timestamp,
                "processing_timestamp": meta.processing_timestamp,
                "correlation_id": meta.correlation_id,
                "batch_id": None,
                "stream_id": None,
                "schema_version": meta.schema_version,
                "pipeline_version": meta.pipeline_version,
                "processing_status": "PENDING",
                "processing_duration_ms": 0.0
            },
            "identity_context": parsed.get("identity_context", {}),
            "asset_context": parsed.get("asset_context", {}),
            "network_context": parsed.get("network_context", {}),
            "financial_context": parsed.get("financial_context", {}),
            "security_context": parsed.get("security_context", {}),
            "threat_context": parsed.get("threat_context", {}),
            "fraud_context": {},
            "geo_context": parsed.get("geo_context", {}),
            "behavioral_features": {},
            "relationship_context": {},
            "normalized_event_data": parsed.get("normalized_event_data", {})
        }

    def _create_error_cee(self, uee: UniversalEventEnvelope, stage: str, error_msg: str, start_time: float) -> Dict[str, Any]:
        meta = uee.metadata
        current_time_str = datetime.utcnow().replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        
        return {
            "event_information": {
                "event_uuid": meta.event_uuid,
                "original_event_id": meta.original_event_id,
                "event_type": meta.event_type,
                "event_category": meta.event_category,
                "source_system": meta.source_system,
                "source_vendor": meta.source_vendor,
                "normalized_timestamp": current_time_str,
                "original_timestamp": meta.original_timestamp,
                "ingestion_timestamp": meta.ingestion_timestamp,
                "processing_timestamp": meta.processing_timestamp,
                "correlation_id": meta.correlation_id,
                "batch_id": None,
                "stream_id": None,
                "schema_version": meta.schema_version,
                "pipeline_version": meta.pipeline_version,
                "processing_status": "ERROR",
                "processing_duration_ms": (time.perf_counter() - start_time) * 1000.0
            },
            "identity_context": {},
            "asset_context": {},
            "network_context": {},
            "financial_context": {},
            "security_context": {},
            "threat_context": {},
            "fraud_context": {},
            "geo_context": {},
            "behavioral_features": {},
            "relationship_context": {},
            "normalized_event_data": {}
        }

    async def process_batch(self, uee_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        results = []
        for raw in uee_events:
            try:
                processed = await self.process_event(raw)
                results.append(processed)
            except PipelineError as e:
                results.append({
                    "error_code": e.error_code,
                    "error_message": e.error_message,
                    "processing_stage": e.processing_stage,
                    "event_uuid": e.event_uuid,
                    "recommended_action": e.recommended_action
                })
            except Exception as e:
                event_uuid = raw.get("metadata", {}).get("event_uuid")
                results.append({
                    "error_code": "UNEXPECTED_FAILURE",
                    "error_message": str(e),
                    "processing_stage": "orchestration",
                    "event_uuid": event_uuid,
                    "recommended_action": "Review system log diagnostics and pipeline configurations."
                })
        return results
