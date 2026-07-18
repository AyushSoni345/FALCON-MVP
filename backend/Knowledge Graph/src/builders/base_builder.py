from abc import ABC, abstractmethod
from typing import List
from src.models.input_event import ContextEnrichedEvent
from src.models.node import Node

class BaseBuilder(ABC):
    @abstractmethod
    def build_nodes(self, event: ContextEnrichedEvent) -> List[Node]:
        pass
