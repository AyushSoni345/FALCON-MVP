from src.storage.networkx_store import NetworkXGraphStore
from src.ingress.fastapi_adapter import FastAPIIngressAdapter
from src.core.graph_index_manager import GraphIndexManager
from src.core.graph_state_manager import GraphStateManager
from src.core.graph_rules_engine import GraphRulesEngine
from src.core.relationship_engine import RelationshipEngine
from src.core.graph_path_engine import GraphPathEngine
from src.core.graph_metrics_engine import GraphMetricsEngine
from src.core.graph_context_generator import GraphContextGenerator
from src.core.entity_extractor import EntityExtractor
from src.core.security_graph_event_producer import SecurityGraphEventProducer
from src.utils.logger import get_logger

logger = get_logger(__name__)

def create_app():
    logger.info("Initializing Module 3 - Security Context Graph components")
    
    store = NetworkXGraphStore()
    index_manager = GraphIndexManager()
    state_manager = GraphStateManager(store, index_manager)
    
    rules_engine = GraphRulesEngine()
    relationship_engine = RelationshipEngine(rules_engine)
    path_engine = GraphPathEngine(store)
    metrics_engine = GraphMetricsEngine(store)
    context_generator = GraphContextGenerator(store)
    extractor = EntityExtractor()
    
    producer = SecurityGraphEventProducer(
        state_manager=state_manager,
        extractor=extractor,
        relationship_engine=relationship_engine,
        path_engine=path_engine,
        metrics_engine=metrics_engine,
        context_generator=context_generator
    )
    
    ingress = FastAPIIngressAdapter()
    ingress.set_processor(producer.process_event)
    
    return ingress

ingress_app = create_app()
app = ingress_app.app

if __name__ == "__main__":
    ingress_app.start()
