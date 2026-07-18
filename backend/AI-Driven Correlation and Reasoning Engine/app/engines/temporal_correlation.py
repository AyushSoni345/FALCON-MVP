from typing import Any, Dict, List
from module4.app.models.models import SecurityGraphEvent
from module4.app.engines.interfaces import BaseTemporalCorrelationEngine
from module4.app.configuration.config import settings

class TemporalCorrelationEngine(BaseTemporalCorrelationEngine):
    """
    Chronologically orders and correlates events by normalized timestamp.
    Calculates time gaps, duration, and groups events within temporal windows.
    """

    def correlate(self, events: List[SecurityGraphEvent]) -> Dict[str, Any]:
        if not events:
            return {
                "ordered_events": [],
                "duration_seconds": 0.0,
                "temporal_groups": [],
                "timeline_confidence": 1.0,
                "observations": ["No events to correlate."]
            }

        # Order events by normalized_timestamp
        ordered_events = sorted(
            events,
            key=lambda e: (e.event_context.normalized_timestamp, e.event_context.event_uuid)
        )

        start_time = ordered_events[0].event_context.normalized_timestamp
        end_time = ordered_events[-1].event_context.normalized_timestamp
        duration = (end_time - start_time).total_seconds()

        observations = [
            f"Correlated {len(events)} events across a timeframe of {duration:.2f} seconds.",
            f"Timeline started at {start_time.isoformat()} and ended at {end_time.isoformat()}."
        ]

        # Detect rapid progression
        time_gaps = []
        for i in range(len(ordered_events) - 1):
            t1 = ordered_events[i].event_context.normalized_timestamp
            t2 = ordered_events[i + 1].event_context.normalized_timestamp
            gap = (t2 - t1).total_seconds()
            time_gaps.append(gap)

        fast_transition_detected = any(
            gap <= settings.IMMEDIATE_CORRELATION_WINDOW_SECONDS for gap in time_gaps
        )
        if fast_transition_detected:
            observations.append(
                "Immediate/rapid event transition detected (<= 60 seconds gap)."
            )
            timeline_confidence = 0.95
        else:
            timeline_confidence = 0.85

        # Group into correlation windows
        # If the gap between successive events is less than the medium duration window, group them
        temporal_groups = []
        current_group = []
        for idx, event in enumerate(ordered_events):
            if not current_group:
                current_group.append(event)
            else:
                last_event = current_group[-1]
                gap = (event.event_context.normalized_timestamp - last_event.event_context.normalized_timestamp).total_seconds()
                if gap <= settings.MEDIUM_DURATION_WINDOW_SECONDS:
                    current_group.append(event)
                else:
                    temporal_groups.append([e.event_context.event_uuid for e in current_group])
                    current_group = [event]
        if current_group:
            temporal_groups.append([e.event_context.event_uuid for e in current_group])

        return {
            "ordered_events": ordered_events,
            "duration_seconds": duration,
            "temporal_groups": temporal_groups,
            "timeline_confidence": timeline_confidence,
            "observations": observations,
            "time_gaps": time_gaps
        }
