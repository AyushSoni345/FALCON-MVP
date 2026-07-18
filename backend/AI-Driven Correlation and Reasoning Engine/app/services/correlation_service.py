import logging
import time
from typing import List
from module4.app.models.models import SecurityGraphEvent, CorrelatedSecurityIncident
from module4.app.validators.validators import SecurityGraphEventValidator
from module4.app.core.container import container
from module4.app.exceptions.exceptions import CorrelationException, InvalidSecurityGraphEventException

logger = logging.getLogger("FALCON.Module4.CorrelationService")

class CorrelationService:
    """
    Orchestrates the workflow of receiving SecurityGraphEvents, running them
    through the validation pipeline, executing each AI reasoning engine sequentially,
    assembling the final incident, and storing it in the repository.
    """

    def __init__(self) -> None:
        self.temporal_engine = container.temporal_engine
        self.graph_engine = container.graph_engine
        self.pattern_engine = container.pattern_engine
        self.attack_sequence_engine = container.attack_sequence_engine
        self.evidence_validator = container.evidence_validator
        self.hypothesis_generator = container.hypothesis_generator
        self.confidence_engine = container.confidence_engine
        self.incident_builder = container.incident_builder
        self.repository = container.incident_repository

    async def correlate_events(self, events: List[SecurityGraphEvent]) -> CorrelatedSecurityIncident:
        """
        Orchestrates the correlation pipeline asynchronously.
        """
        if not events:
            raise CorrelationException("Cannot correlate an empty list of SecurityGraphEvents.")

        start_time = time.perf_counter()
        correlation_id = events[0].event_context.correlation_id
        
        logger.info(f"Starting correlation workflow for {len(events)} events (Correlation ID: {correlation_id})")

        # 1. Validation Pipeline
        try:
            for idx, event in enumerate(events):
                SecurityGraphEventValidator.validate_event(event)
        except InvalidSecurityGraphEventException as e:
            logger.error(f"Validation failed during correlation setup: {e.message}")
            raise e
        except Exception as e:
            logger.error(f"Unexpected error during input validation: {str(e)}")
            raise InvalidSecurityGraphEventException(f"Input validation failure: {str(e)}")

        try:
            # 2. Temporal Correlation
            temporal_res = self.temporal_engine.correlate(events)
            
            # 3. Graph Traversal & Reasoning
            graph_res = self.graph_engine.reason(events, temporal_res)
            
            # 4. Pattern Recognition
            patterns_res = self.pattern_engine.recognize(events, temporal_res, graph_res)
            
            # 5. Attack Sequence Reconstruction
            sequence_res = self.attack_sequence_engine.reconstruct(events, temporal_res, graph_res, patterns_res)
            
            # 6. Evidence Validation
            evidence_res = self.evidence_validator.validate_evidence(events, sequence_res, graph_res)
            
            # 7. Threat Hypothesis Generation
            hypotheses = self.hypothesis_generator.generate_hypotheses(events, evidence_res)
            
            # 8. Confidence Assessment
            confidence_res = self.confidence_engine.calculate_confidence(events, evidence_res, hypotheses)

            # 10. Construct CorrelatedSecurityIncident
            incident = self.incident_builder.build_incident(
                events=events,
                temporal_output=temporal_res,
                graph_output=graph_res,
                patterns_output=patterns_res,
                sequence_output=sequence_res,
                evidence_output=evidence_res,
                hypotheses=hypotheses,
                confidence_output=confidence_res
            )

            # 11. Store in Repository
            self.repository.save(incident)
            
            duration = time.perf_counter() - start_time
            logger.info(
                f"Successfully completed correlation in {duration*1000:.2f}ms. "
                f"Generated Incident ID: {incident.incident_info.incident_id} (Type: {incident.incident_info.incident_type})"
            )
            
            return incident
            
        except Exception as e:
            logger.exception(f"Pipeline error during event correlation: {str(e)}")
            raise CorrelationException(f"Failed to execute correlation pipeline: {str(e)}")
