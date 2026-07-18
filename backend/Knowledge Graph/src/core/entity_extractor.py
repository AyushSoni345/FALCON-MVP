from typing import List
from src.models.input_event import ContextEnrichedEvent
from src.models.node import Node
from src.builders.builders import (
    IdentityBuilder, DeviceBuilder, SessionBuilder, 
    TransactionBuilder, NetworkBuilder, ThreatBuilder, AssetBuilder,
    SecurityLogBuilder
)

class EntityExtractor:
    def __init__(self):
        self.builders = [
            IdentityBuilder(),
            DeviceBuilder(),
            SessionBuilder(),
            TransactionBuilder(),
            NetworkBuilder(),
            ThreatBuilder(),
            AssetBuilder(),
            SecurityLogBuilder()
        ]
        
    def extract_nodes(self, event: ContextEnrichedEvent) -> List[Node]:
        nodes = []
        for builder in self.builders:
            nodes.extend(builder.build_nodes(event))
        return nodes
