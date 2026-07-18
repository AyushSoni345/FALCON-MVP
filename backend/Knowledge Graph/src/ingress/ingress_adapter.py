from abc import ABC, abstractmethod
from typing import Callable, Awaitable
from src.models.input_event import ContextEnrichedEvent
from src.models.output_event import SecurityGraphEvent

class IngressAdapter(ABC):
    def __init__(self):
        self.processor: Callable[[ContextEnrichedEvent], Awaitable[SecurityGraphEvent]] = None
        
    def set_processor(self, processor: Callable[[ContextEnrichedEvent], Awaitable[SecurityGraphEvent]]):
        """Sets the callback to be invoked when an event is received."""
        self.processor = processor
        
    @abstractmethod
    def start(self, host: str, port: int) -> None:
        """Starts the ingress listener."""
        pass
