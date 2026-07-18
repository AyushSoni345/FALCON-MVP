from src.models.input_event import ContextEnrichedEvent

class EventValidator:
    def validate(self, event_payload: dict) -> ContextEnrichedEvent:
        return ContextEnrichedEvent(**event_payload)
