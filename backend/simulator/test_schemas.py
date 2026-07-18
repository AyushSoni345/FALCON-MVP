import sys
import os
from datetime import datetime, timezone

# Add the parent directory to path so we can import simulator
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from simulator.models import CommonEnvelope
from simulator.scenarios import build_scenario_events, SCENARIOS_MAP

def test_all_scenarios_validation():
    import sys
    sys.stdout.reconfigure(encoding='utf-8')
    print("=" * 60)
    print("🧪 Running Pydantic Schema Validation Tests... 🧪")
    print("=" * 60)
    
    start_time = datetime.now(timezone.utc)
    all_success = True
    
    for name in SCENARIOS_MAP.keys():
        print(f"Testing Scenario: {name}...")
        try:
            # Build the scenario events
            events = build_scenario_events(name, start_time)
            
            if not events:
                print(f"❌ Error: Scenario {name} returned no events!")
                all_success = False
                continue
                
            print(f"  Generated {len(events)} events.")
            
            # Validate each event against the Pydantic CommonEnvelope model
            for i, ev in enumerate(events):
                # Pydantic validates on instantiation, but let's double check model dump and load
                dumped = ev.model_dump()
                loaded = CommonEnvelope.model_validate(dumped)
                
                # Check that envelope contains required fields
                assert loaded.event_id is not None
                assert loaded.event_type is not None
                assert loaded.source_system is not None
                assert loaded.timestamp is not None
                assert loaded.severity is not None
                assert loaded.raw_payload is not None
                
            # Verify timestamps are monotonic
            timestamps = [datetime.strptime(ev.timestamp, "%Y-%m-%dT%H:%M:%SZ") for ev in events]
            is_sorted = all(timestamps[i] <= timestamps[i+1] for i in range(len(timestamps)-1))
            if not is_sorted:
                print(f"  ❌ Timestamp Sequence Error: Timestamps in {name} are not in chronological order!")
                all_success = False
            else:
                print(f"  ✅ Timestamps are chronologically consistent.")
                
            # Verify correlation ID is reused across all events in the scenario
            corr_ids = [ev.correlation_id for ev in events if ev.correlation_id]
            if len(set(corr_ids)) > 1:
                print(f"  ❌ Correlation ID Error: Scenario {name} contains multiple correlation IDs: {set(corr_ids)}")
                all_success = False
            elif len(set(corr_ids)) == 1:
                print(f"  ✅ Correlation ID correctly reused: {corr_ids[0]}")
            else:
                print(f"  ⚠️ Warning: No correlation ID found in scenario {name}")
                
            print(f"  ✅ Scenario {name} passed all validation tests.")
            
        except Exception as e:
            print(f"❌ Error validating scenario {name}: {e}")
            import traceback
            traceback.print_exc()
            all_success = False
            
        print("-" * 40)
        
    print("=" * 60)
    if all_success:
        print("🎉 ALL SCHEMA VALIDATION TESTS PASSED SUCCESSFULLY! 🎉")
        print("=" * 60)
    else:
        print("❌ SOME SCHEMA VALIDATION TESTS FAILED. CHECK LOGS ABOVE. ❌")
        print("=" * 60)
        assert False, "Some schema validation tests failed."

if __name__ == "__main__":
    try:
        test_all_scenarios_validation()
        sys.exit(0)
    except AssertionError:
        sys.exit(1)
