import sys
import os
import json
from datetime import datetime
from collections import Counter, defaultdict

def main():
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')

    # Path to NDJSON
    default_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "events.ndjson"))
    file_path = sys.argv[1] if len(sys.argv) > 1 else default_path

    print("=" * 60)
    print(f"🔍 Starting Stream Verification: {file_path} 🔍")
    print("=" * 60)

    if not os.path.exists(file_path):
        print(f"❌ Error: File not found at {file_path}")
        print("STREAM VALIDATION FAILED")
        sys.exit(1)

    # Core stats trackers
    total_events = 0
    invalid_json_lines = 0
    missing_envelope_fields = 0
    missing_raw_payload = 0
    invalid_timestamps = 0
    chronology_violations = 0
    relationship_violations = 0
    balance_math_violations = 0
    correlation_id_misuse = 0

    event_ids = set()
    duplicate_event_ids = set()

    event_types = []
    sessions = set()
    customers = set()
    employees = set()

    # Relationship trackers: group context by session_id/correlation_id
    session_contexts = defaultdict(list)
    correlation_contexts = defaultdict(list)

    # Read and parse file line by line
    with open(file_path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            
            total_events += 1
            
            # Check 6: Invalid JSON Lines
            try:
                event = json.loads(line)
            except Exception as e:
                invalid_json_lines += 1
                print(f"Line {line_num}: Failed to parse JSON: {e}")
                continue

            # Check 5: Missing required envelope fields
            required_fields = ["event_id", "event_type", "source_system", "timestamp", "severity", "raw_payload"]
            missing_fields = [f for f in required_fields if f not in event]
            if missing_fields:
                missing_envelope_fields += 1
                print(f"Line {line_num} (ID: {event.get('event_id', 'Unknown')}): Missing envelope fields: {missing_fields}")
                continue

            # Check 1: Duplicate event_id
            ev_id = event["event_id"]
            if ev_id in event_ids:
                duplicate_event_ids.add(ev_id)
            else:
                event_ids.add(ev_id)

            # Check 9: Missing raw_payload
            raw_payload = event["raw_payload"]
            if not isinstance(raw_payload, dict) or not raw_payload:
                missing_raw_payload += 1
                print(f"Line {line_num} (ID: {ev_id}): raw_payload is missing or empty")

            # Check 3: Invalid timestamps (UTC ending in Z)
            timestamp_str = event["timestamp"]
            try:
                if not timestamp_str.endswith("Z"):
                    raise ValueError("Timestamp must end with 'Z' indicating UTC")
                # Parse timestamp
                dt = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%SZ")
                event["parsed_time"] = dt
            except Exception as e:
                invalid_timestamps += 1
                print(f"Line {line_num} (ID: {ev_id}): Invalid timestamp format '{timestamp_str}': {e}")
                event["parsed_time"] = None

            # Collect metrics
            event_types.append(event["event_type"])
            
            cust_id = event.get("customer_id")
            if cust_id:
                customers.add(cust_id)
                
            emp_id = event.get("employee_id")
            if emp_id:
                employees.add(emp_id)
                
            sess_id = event.get("session_id")
            if sess_id:
                sessions.add(sess_id)
                # Map to session context for later relationship validation
                session_contexts[sess_id].append((line_num, event))
                
            corr_id = event.get("correlation_id")
            if corr_id:
                correlation_contexts[corr_id].append((line_num, event))

            # Check 8: Invalid balance calculations for core banking events
            if event["event_type"] == "core_banking" and event["parsed_time"]:
                payload = event["raw_payload"]
                bal_before = payload.get("balance_before")
                bal_after = payload.get("balance_after")
                amount = payload.get("amount")
                txt_type = payload.get("transaction_type")
                status = payload.get("status")

                if all(v is not None for v in [bal_before, bal_after, amount]):
                    if txt_type in ["TRANSFER", "WITHDRAWAL"] and status in ["APPROVED", "PENDING"]:
                        expected = round(bal_before - amount, 2)
                        if abs(bal_after - expected) > 0.02:
                            balance_math_violations += 1
                            print(f"Line {line_num} (ID: {ev_id}): Balance math error! Before={bal_before}, Amt={amount}, After={bal_after}, Expected={expected}")
                    elif txt_type == "DEPOSIT" and status in ["APPROVED", "PENDING"]:
                        expected = round(bal_before + amount, 2)
                        if abs(bal_after - expected) > 0.02:
                            balance_math_violations += 1
                            print(f"Line {line_num} (ID: {ev_id}): Balance math error! Before={bal_before}, Amt={amount}, After={bal_after}, Expected={expected}")
                    elif status == "DECLINED":
                        if abs(bal_before - bal_after) > 0.01:
                            balance_math_violations += 1
                            print(f"Line {line_num} (ID: {ev_id}): Balance mutated ({bal_before} -> {bal_after}) on DECLINED transaction")

    # Check 2: Duplicate correlation_id misuse
    # Misuse is defined as: A correlation ID mapped to more than one unique customer or employee
    for corr_id, evs in correlation_contexts.items():
        corr_customers = set(ev[1].get("customer_id") for ev in evs if ev[1].get("customer_id"))
        corr_employees = set(ev[1].get("employee_id") for ev in evs if ev[1].get("employee_id"))
        if len(corr_customers) > 1 or len(corr_employees) > 1:
            correlation_id_misuse += 1
            print(f"Correlation ID Misuse: {corr_id} is associated with multiple entities: Customers={corr_customers}, Employees={corr_employees}")

    # Check 7 & 4: Broken relationship consistency & Chronological ordering
    for sess_id, evs in session_contexts.items():
        # Sort events by stream appearance line number
        evs_sorted = sorted(evs, key=lambda x: x[0])
        
        # Verify relationships are consistent (User, Device, and IP must not change mid-session)
        cust_ids = set(ev[1].get("customer_id") for ev in evs_sorted if ev[1].get("customer_id"))
        emp_ids = set(ev[1].get("employee_id") for ev in evs_sorted if ev[1].get("employee_id"))
        device_ids = set(ev[1].get("device_id") for ev in evs_sorted if ev[1].get("device_id"))
        ips = set(ev[1].get("ip_address") for ev in evs_sorted if ev[1].get("ip_address"))
        
        if len(cust_ids) > 1 or len(emp_ids) > 1 or len(device_ids) > 1 or len(ips) > 1:
            relationship_violations += 1
            print(f"Relationship Violation in Session {sess_id}: Multiple distinct entities bound mid-session! Customers={cust_ids}, Employees={emp_ids}, Devices={device_ids}, IPs={ips}")

        # Verify chronology within same session
        # Timestamps must be monotonic (non-decreasing) as events appear in sequence
        prev_time = None
        for line_num, ev in evs_sorted:
            curr_time = ev.get("parsed_time")
            if curr_time and prev_time:
                if curr_time < prev_time:
                    chronology_violations += 1
                    print(f"Chronology Violation in Session {sess_id} at line {line_num}: Event time ({ev['timestamp']}) is before previous event time ({prev_time.strftime('%Y-%m-%dT%H:%M:%SZ')})")
            if curr_time:
                prev_time = curr_time

    # Group chronology check for Correlation IDs as well
    for corr_id, evs in correlation_contexts.items():
        evs_sorted = sorted(evs, key=lambda x: x[0])
        prev_time = None
        for line_num, ev in evs_sorted:
            curr_time = ev.get("parsed_time")
            if curr_time and prev_time:
                if curr_time < prev_time:
                    chronology_violations += 1
                    print(f"Chronology Violation in Correlation Chain {corr_id} at line {line_num}: Event time ({ev['timestamp']}) is before previous event time ({prev_time.strftime('%Y-%m-%dT%H:%M:%SZ')})")
            if curr_time:
                prev_time = curr_time

    # Generate Metrics Summary
    print("\n" + "=" * 60)
    print("📊 STREAM METRICS SUMMARY 📊")
    print("=" * 60)
    print(f"Total events generated:            {total_events}")
    print(f"Sessions generated:                {len(sessions)}")
    print(f"Customers generated:               {len(customers)}")
    print(f"Employees generated:               {len(employees)}")
    
    avg_events = total_events / len(sessions) if sessions else 0.0
    print(f"Average events per session:        {avg_events:.2f}")

    # Check 11: Top 10 most common event types
    print("\n🔝 Top 10 Most Common Event Types:")
    type_counts = Counter(event_types)
    for rank, (etype, count) in enumerate(type_counts.most_common(10), 1):
        print(f"  {rank}. {etype.upper():<20} : {count} events")

    # Check 10: Event type distribution (%)
    print("\n📈 Event Type Distribution:")
    for etype, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
        pct = (count / total_events) * 100 if total_events else 0.0
        print(f"  - {etype.upper():<20} : {pct:.2f}%")

    # Check 17: Validation Summary
    print("\n" + "=" * 60)
    print("🛡️ VALIDATION REPORT SUMMARY 🛡️")
    print("=" * 60)
    
    failed_checks = 0
    
    def report_check(name, error_count):
        nonlocal failed_checks
        status = "PASSED" if error_count == 0 else "FAILED"
        marker = "✅" if error_count == 0 else "❌"
        print(f"{marker} {name:<45} : {status:<8} ({error_count} issues)")
        if error_count > 0:
            failed_checks += 1

    report_check("1. Duplicate event_id Checks", len(duplicate_event_ids))
    report_check("2. Duplicate correlation_id Misuse Checks", correlation_id_misuse)
    report_check("3. Invalid Timestamps Checks", invalid_timestamps)
    report_check("4. Chronological Ordering Checks", chronology_violations)
    report_check("5. Missing Envelope Fields Checks", missing_envelope_fields)
    report_check("6. Invalid JSON Lines Checks", invalid_json_lines)
    report_check("7. Customer/Session/Device Relationships Checks", relationship_violations)
    report_check("8. Invalid Balance Calculations Checks", balance_math_violations)
    report_check("9. Missing raw_payload Checks", missing_raw_payload)

    print("=" * 60)
    if failed_checks == 0:
        print("🎉 ALL STREAM VALIDATIONS PASSED 🎉")
        sys.exit(0)
    else:
        print("🚨 STREAM VALIDATION FAILED 🚨")
        sys.exit(1)

if __name__ == "__main__":
    main()
