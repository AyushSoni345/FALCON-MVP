import uuid
from typing import List, Tuple, Dict, Any
from src.models.input_event import ContextEnrichedEvent
from src.models.output_event import SecurityGraphEvent, GraphStateMetadata
from src.models.graph_snapshot import GraphSnapshot, GraphPath
from src.models.node import Node
from src.models.relationship import Relationship
from src.core.graph_state_manager import GraphStateManager
from src.core.graph_metrics_engine import GraphMetricsEngine
from src.core.graph_context_generator import GraphContextGenerator
from src.core.graph_path_engine import GraphPathEngine
from src.core.entity_extractor import EntityExtractor
from src.core.relationship_engine import RelationshipEngine
from src.utils.logger import get_logger

logger = get_logger(__name__)

class SecurityGraphEventProducer:
    def __init__(self, 
                 state_manager: GraphStateManager,
                 extractor: EntityExtractor,
                 relationship_engine: RelationshipEngine,
                 path_engine: GraphPathEngine,
                 metrics_engine: GraphMetricsEngine,
                 context_generator: GraphContextGenerator):
        self.state_manager = state_manager
        self.extractor = extractor
        self.relationship_engine = relationship_engine
        self.path_engine = path_engine
        self.metrics_engine = metrics_engine
        self.context_generator = context_generator
        
    async def process_event(self, event: ContextEnrichedEvent) -> SecurityGraphEvent:
        event_uuid = event.event_uuid or str(uuid.uuid4())
        correlation_id = event.correlation_id or ""
        
        extracted_nodes = self.extractor.extract_nodes(event)
        logger.info(f"Extracted {len(extracted_nodes)} potential nodes for event {event_uuid}")
        
        snapshot = GraphSnapshot()
        
        event_nodes = []
        for node in extracted_nodes:
            updated_node, is_new = self.state_manager.add_or_update_node(node, event_uuid, correlation_id)
            event_nodes.append(updated_node)
            if is_new:
                snapshot.new_nodes.append(updated_node)
            else:
                snapshot.updated_nodes.append(updated_node)
                
        extracted_rels = self.relationship_engine.build_relationships(event_nodes)
        logger.info(f"Inferred {len(extracted_rels)} potential relationships for event {event_uuid}")
        
        event_rels = []
        for rel in extracted_rels:
            updated_rel, is_new = self.state_manager.add_or_update_relationship(rel)
            event_rels.append(updated_rel)
            if is_new:
                snapshot.new_relationships.append(updated_rel)
            else:
                snapshot.updated_relationships.append(updated_rel)
                
        paths = self.path_engine.discover_paths(event_nodes)
        snapshot.paths = paths
        
        metrics = self.metrics_engine.compute_metrics(event_nodes)
        snapshot.metrics = metrics
        
        context = self.context_generator.generate_context(event_nodes)
        
        metadata = self.state_manager.get_metadata()
        
        event_metadata = {
            "event_uuid": event_uuid,
            "correlation_id": correlation_id,
            "timestamp": event.timestamp or ""
        }
        
        out_event = SecurityGraphEvent(
            event_context=event_metadata,
            graph_nodes=event_nodes,
            graph_relationships=event_rels,
            graph_paths=paths,
            graph_metrics=metrics,
            graph_context=context,
            graph_state_metadata=GraphStateMetadata(**metadata),
            context_enriched_event=event
        )
        
        logger.info(f"Produced SecurityGraphEvent for event {event_uuid} successfully.")
        return out_event
