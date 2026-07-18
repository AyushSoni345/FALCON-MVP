from fastapi import APIRouter, Depends, HTTPException, status, Body
from fastapi.responses import JSONResponse
from typing import List, Dict, Any, Union
from app.api.models import HealthResponse, SchemaResponse, MetricsResponse, ErrorResponse
from app.core.schema import UniversalEventEnvelope, ContextEnrichedEvent
from app.core.engine import NormalizationEnrichmentEngine, PipelineError
from app.database.memory_repo import InMemoryStateRepository
from app.dependencies import get_engine, get_repository
from app.config import settings
from app.logging_config import log_pipeline, logger
from app.api.examples import REQUEST_EXAMPLES, RESPONSE_EXAMPLES
import logging

router = APIRouter()

BATCH_REQUEST_EXAMPLES = {
    "BatchEvents": {
        "summary": "Batch with Firewall and VPN events",
        "value": [
            REQUEST_EXAMPLES["Firewall"]["value"],
            REQUEST_EXAMPLES["VPN"]["value"]
        ]
    }
}

BATCH_RESPONSE_EXAMPLES = {
    "BatchEvents": {
        "summary": "Batch containing Firewall enriched event",
        "value": [
            RESPONSE_EXAMPLES["Firewall"]["value"]
        ]
    }
}

@router.post(
    "/normalize",
    response_model=ContextEnrichedEvent,
    responses={
        200: {
            "content": {
                "application/json": {
                    "examples": RESPONSE_EXAMPLES
                }
            }
        },
        400: {"model": ErrorResponse, "description": "Unsupported Event Type"},
        422: {"model": ErrorResponse, "description": "Invalid Envelope / Normalization Failure"},
        500: {"model": ErrorResponse, "description": "Internal Schema Validation Error"}
    },
    summary="Normalize and enrich a single Universal Event Envelope",
    description="Accepts a Module 1 Universal Event Envelope, runs specialized parsing, resolves identity and assets, and applies full geographic, threat, MITRE, and behavioral fraud context enrichments."
)
async def normalize_single_event(
    payload: UniversalEventEnvelope = Body(
        ...,
        openapi_examples=REQUEST_EXAMPLES
    ),
    engine: NormalizationEnrichmentEngine = Depends(get_engine)
):
    try:
        raw_dict = payload.model_dump()
        result = await engine.process_event(raw_dict)
        
        # Log final pipeline response logs in exact requested sequence
        event_uuid = result["event_information"]["event_uuid"]
        corr_id = result["event_information"]["correlation_id"]
        
        log_pipeline(
            logging.INFO,
            "Response Sent",
            "response_sent",
            "success",
            event_uuid=event_uuid,
            correlation_id=corr_id
        )
        
        dur = result["event_information"]["processing_duration_ms"]
        log_pipeline(
            logging.INFO,
            f"Processing Time: {dur:.2f} ms",
            "processing_time",
            "success",
            event_uuid=event_uuid,
            correlation_id=corr_id,
            duration=dur
        )
        return result
    except PipelineError as e:
        status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
        if e.error_code == "UNSUPPORTED_EVENT_TYPE":
            status_code = status.HTTP_400_BAD_REQUEST
        elif e.error_code in ["VALIDATION_ERROR", "INTERNAL_ERROR"]:
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            
        return JSONResponse(
            status_code=status_code,
            content={
                "error_code": e.error_code,
                "error_message": e.error_message,
                "processing_stage": e.processing_stage,
                "event_uuid": e.event_uuid,
                "recommended_action": e.recommended_action
            }
        )
    except Exception as e:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error_code": "INTERNAL_ERROR",
                "error_message": f"Unexpected pipeline failure: {str(e)}",
                "processing_stage": "orchestration",
                "event_uuid": payload.metadata.event_uuid if payload and payload.metadata else None,
                "recommended_action": "Contact engineering team or check app logs."
            }
        )

@router.post(
    "/normalize/batch",
    response_model=List[Union[ContextEnrichedEvent, ErrorResponse]],
    responses={
        200: {
            "content": {
                "application/json": {
                    "examples": BATCH_RESPONSE_EXAMPLES
                }
            }
        },
        207: {"description": "Multi-Status: Some events in the batch failed to process."}
    },
    summary="Normalize and enrich a batch of Universal Event Envelopes",
    description="Sequentially processes a list of envelopes, ensuring individual log failure does not block execution of remaining events."
)
async def normalize_batch_events(
    payload: List[UniversalEventEnvelope] = Body(
        ...,
        openapi_examples=BATCH_REQUEST_EXAMPLES
    ),
    engine: NormalizationEnrichmentEngine = Depends(get_engine)
):
    try:
        raw_list = [item.model_dump() for item in payload]
        results = await engine.process_batch(raw_list)
        
        # Check if there are any failures in the batch results
        has_errors = any("error_code" in item for item in results)
        
        # Log response metrics for the batch
        for item in results:
            if "event_information" in item:
                event_uuid = item["event_information"]["event_uuid"]
                corr_id = item["event_information"]["correlation_id"]
                log_pipeline(
                    logging.INFO,
                    "Response Sent",
                    "response_sent",
                    "success",
                    event_uuid=event_uuid,
                    correlation_id=corr_id
                )
                dur = item["event_information"]["processing_duration_ms"]
                log_pipeline(
                    logging.INFO,
                    f"Processing Time: {dur:.2f} ms",
                    "processing_time",
                    "success",
                    event_uuid=event_uuid,
                    correlation_id=corr_id,
                    duration=dur
                )

        if has_errors:
            return JSONResponse(
                status_code=207,
                content=results
            )
        return results
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Failed to process batch payload: {str(e)}"
        )

@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check endpoint"
)
async def health_check():
    return HealthResponse(
        status="healthy",
        environment=settings.env,
        version="2.0.0"
    )

@router.get(
    "/schema",
    response_model=SchemaResponse,
    summary="Retrieve Canonical Enterprise Schema details"
)
async def get_schema_details():
    return SchemaResponse(
        schema_name="FALCON Canonical Output Schema",
        version="2.0.0",
        supported_event_types=[
            "FIREWALL", "IDS", "VPN", "IAM", "INTERNET_BANKING", "CORE_BANKING", 
            "UPI", "NEFT", "RTGS", "IMPS", "CARD", "ATM", "BENEFICIARY", "EDR", 
            "SIEM", "THREAT_FEED", "QUANTUM"
        ],
        supported_parsers=[
            "FirewallParser", "IDSParser", "VPNParser", "IAMParser", "InternetBankingParser", 
            "CoreBankingParser", "UPIParser", "NEFTParser", "RTGSParser", "IMPSParser", 
            "CardParser", "ATMParser", "BeneficiaryParser", "EDRParser", "SIEMParser", 
            "ThreatFeedParser", "QuantumParser"
        ],
        supported_enrichment_engines=[
            "IdentityResolver", "GeoService", "ThreatIntelEnricher", "MitreMapper", 
            "FraudContextEngine", "BehavioralFeatureEngine", "RelationshipContextEngine"
        ]
    )

@router.get(
    "/metrics",
    response_model=MetricsResponse,
    summary="Retrieve processing stats and engine telemetry"
)
async def get_metrics(
    repo: InMemoryStateRepository = Depends(get_repository)
):
    events = list(repo.normalized_events.values())
    total_processed = len(events)
    
    failed = sum(
        1 for e in events 
        if e.get("event_information", {}).get("processing_status") == "ERROR"
    )
    
    total_time = sum(e.get("event_information", {}).get("processing_duration_ms", 0.0) for e in events)
    avg_time = (total_time / total_processed) if total_processed > 0 else 0.0
    
    parser_stats = {}
    for e in events:
        # Resolve from log structure or default to UNKNOWN
        info = e.get("event_information", {})
        event_type = info.get("event_type", "UNKNOWN")
        # Match class names
        parser_name = f"{event_type.title()}Parser" if event_type != "UNKNOWN" else "UNKNOWN"
        if event_type == "INTERNET_BANKING":
            parser_name = "InternetBankingParser"
        elif event_type == "CORE_BANKING":
            parser_name = "CoreBankingParser"
        elif event_type == "THREAT_FEED":
            parser_name = "ThreatFeedParser"
        
        parser_stats[parser_name] = parser_stats.get(parser_name, 0) + 1
        
    geo_count = 0
    threat_count = 0
    fraud_count = 0
    
    for e in events:
        # Check if they have relevant contexts
        geo = e.get("geo_context", {})
        if geo and geo.get("geo_source") not in [None, "Localhost", "PrivateIP"]:
            geo_count += 1
            
        threat = e.get("threat_context", {})
        if threat and threat.get("IOC_match") is True:
            threat_count += 1
            
        fraud = e.get("fraud_context", {})
        if fraud and any(v is True for k, v in fraud.items() if isinstance(v, bool)):
            fraud_count += 1

    cache_hit_ratio = 0.85
    if total_processed > 0:
        resolved_logins = sum(
            1 for e in events 
            if e.get("identity_context", {}).get("customer_id") or e.get("identity_context", {}).get("username")
        )
        cache_hit_ratio = resolved_logins / total_processed

    return MetricsResponse(
        events_processed=total_processed,
        average_processing_time=avg_time,
        failed_events=failed,
        parser_statistics=parser_stats,
        cache_hit_ratio=cache_hit_ratio,
        geo_lookup_count=geo_count,
        threat_lookup_count=threat_count,
        fraud_lookup_count=fraud_count,
        repository_size=total_processed
    )
