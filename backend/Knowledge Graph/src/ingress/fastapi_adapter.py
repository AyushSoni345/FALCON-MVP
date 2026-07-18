import os
import uvicorn
from fastapi import FastAPI, HTTPException
from src.ingress.ingress_adapter import IngressAdapter
from src.models.input_event import ContextEnrichedEvent
from src.models.output_event import SecurityGraphEvent
from src.utils.logger import get_logger

logger = get_logger(__name__)

class FastAPIIngressAdapter(IngressAdapter):
    def __init__(self):
        super().__init__()
        self.app = FastAPI(title="Security Context Graph - Module 3")
        self.latest_graph_event = None
        self._setup_routes()
        
    def _setup_routes(self):
        @self.app.post("/events", response_model=SecurityGraphEvent, response_model_by_alias=True)
        async def process_event(event: ContextEnrichedEvent):
            if not self.processor:
                logger.error("Event processor not set in FastAPIIngressAdapter")
                raise HTTPException(status_code=500, detail="Event processor not configured")
            
            try:
                result = await self.processor(event)
                self.latest_graph_event = result
                return result
            except Exception as e:
                logger.error(f"Error processing event: {str(e)}")
                raise HTTPException(status_code=500, detail=str(e))
                
        @self.app.get("/health")
        def health_check():
            return {"service": "Module 3 - Knowledge Graph", "status": "healthy"}
            
        @self.app.get("/graph/latest")
        def get_latest_graph():
            if not self.latest_graph_event:
                # Return a dummy empty visualizer if nothing is processed yet
                return {"security_knowledge_graph_visualizer": {"nodes": [], "edges": []}}
            return {"security_knowledge_graph_visualizer": self.latest_graph_event.security_knowledge_graph_visualizer.model_dump(by_alias=True)}

    def start(self, host: str = "0.0.0.0", port: int = None) -> None:
        port = port or int(os.environ.get("GRAPH_PORT", 8003))
        logger.info(f"Starting FastAPI server on {host}:{port}")
        uvicorn.run(self.app, host=host, port=port)
