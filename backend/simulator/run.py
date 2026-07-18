import os
import sys
import json

# Add parent directory to sys.path to allow execution as python simulator/run.py
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time
import argparse
from datetime import datetime, timezone
from simulator.config import state
from simulator.engine import engine
from simulator.scenarios import SCENARIOS_MAP

def main():
    # Configure stdout to UTF-8 to prevent encoding errors on Windows when writing json
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')

    parser = argparse.ArgumentParser(
        description="🏦 FinGuard AI Headless Event Simulator CLI 🏦",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Available Scenarios:
  Normal Scenarios:
    normal_banking         Customer Mobile/Net Banking session
    normal_employee        Employee daily workstation session
    normal_atm             Atm cash withdrawal transaction
    normal_card            Normal merchant Card POS transaction
    
  Attack Scenarios:
    attack_credential_theft    Internal EDR LSASS alert & external Tor login transfer
    attack_malware             Ransomware execution, Wizard Spider C2 & HNDL exfil
    attack_brute_force         Failed IAM logins, firewall denies, and Admin escalation
    attack_insider             Anomalous 2 AM DBA database archive HNDL export
    attack_ato                 Mumbai login vs Germany impossible travel, UPI transfer
    attack_card_fraud          Mumbai starbucks vs Milan gucci transaction declines
    attack_atm_jackpotting     ATM local technician login, PLOUTUS malware, large cashouts
        """
    )
    
    parser.add_argument(
        "-o", "--output",
        choices=["file", "stdout", "http"],
        default="file",
        help="Target event output mode (default: file)"
    )
    parser.add_argument(
        "-f", "--file-path",
        default=os.path.abspath(os.path.join(os.path.dirname(__file__), "events.ndjson")),
        help="Output log path if in file mode (default: simulator/events.ndjson)"
    )
    parser.add_argument(
        "-u", "--url",
        default="",
        help="Target endpoint ingestion URL if in http mode (e.g., http://localhost:8000/api/v1/ingest)"
    )
    parser.add_argument(
        "-r", "--rate",
        type=float,
        default=1.0,
        help="Average event generation rate per second (default: 1.0)"
    )
    parser.add_argument(
        "-p", "--ratio",
        type=float,
        default=0.35,
        help="Ratio of suspicious/malicious events generated (0.0 to 1.0, default: 0.35)"
    )
    parser.add_argument(
        "-t", "--trigger",
        choices=list(SCENARIOS_MAP.keys()),
        default=None,
        help="Inject a single specific scenario instantly and exit after its timeline completes"
    )
    parser.add_argument(
        "-d", "--duration",
        type=float,
        default=None,
        help="Run simulation for a fixed duration in seconds, then exit"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Print helper logs and status updates to stderr"
    )

    args = parser.parse_args()

    # Validate inputs
    if args.rate <= 0:
        sys.stderr.write("Error: Event generation rate must be greater than 0.\n")
        sys.exit(1)
        
    if args.ratio < 0.0 or args.ratio > 1.0:
        sys.stderr.write("Error: Malicious event ratio must be between 0.0 and 1.0 inclusive.\n")
        sys.exit(1)
        
    if args.duration is not None and args.duration <= 0:
        sys.stderr.write("Error: Simulation duration must be greater than 0.\n")
        sys.exit(1)

    # Configure state properties
    state.rate = args.rate
    state.malicious_ratio = args.ratio
    state.log_path = args.file_path

    # Configure engine properties
    engine.output_mode = args.output
    engine.http_url = args.url
    engine.verbose = args.verbose

    # Validate HTTP URL if HTTP mode selected
    if args.output == "http" and not args.url:
        sys.stderr.write("[!] Error: In HTTP mode, you must provide target ingestion URL via --url / -u.\n")
        sys.exit(1)

    # Verbose startup banner
    if args.verbose:
        sys.stderr.write("=" * 60 + "\n")
        sys.stderr.write("🏦 FinGuard AI Event Simulation Layer (Headless Mode) 🏦\n")
        sys.stderr.write("=" * 60 + "\n")
        sys.stderr.write(f"[*] Configured Rate: {state.rate} events/sec\n")
        sys.stderr.write(f"[*] Configured Ratio: {state.malicious_ratio * 100:.0f}% Malicious / {100 - state.malicious_ratio * 100:.0f}% Normal\n")
        sys.stderr.write(f"[*] Output Channel: {args.output.upper()}\n")
        if args.output == "file":
            sys.stderr.write(f"[*] Target Log File: {state.log_path}\n")
        elif args.output == "http":
            sys.stderr.write(f"[*] Target Ingestion Endpoint: {args.url}\n")
        sys.stderr.write("=" * 60 + "\n")

    # Mode 1: Single scenario trigger and exit
    if args.trigger:
        if args.verbose:
            sys.stderr.write(f"[*] Triggering single scenario: {args.trigger}\n")
        
        # We start the engine, trigger the scenario, wait for the events to be emitted, and stop
        engine.output_mode = args.output
        engine.verbose = args.verbose
        
        # Pre-schedule the scenario
        engine.trigger_scenario_manually(args.trigger)
        
        # The trigger will schedule events at offsets like 0.0, 1.0, 2.0...
        # Let's find the max execution time
        max_t = 0.0
        for item in engine.event_queue:
            max_t = max(max_t, item["run_at"])
            
        # Start execution loop briefly in current thread
        engine.running = True
        
        if args.verbose:
            sys.stderr.write(f"[*] Running execution loop until scenario timeline completes (~{max_t - time.time():.1f} seconds)...\n")
            
        try:
            while engine.running and engine.event_queue:
                now = time.time()
                ready = []
                with engine.lock:
                    while engine.event_queue and engine.event_queue[0]["run_at"] <= now:
                        ready.append(engine.event_queue.pop(0))
                
                # Emit
                for item in ready:
                    ev = item["event"]
                    ev_dict = ev.model_dump()
                    ev_json = json.dumps(ev_dict)
                    
                    if args.output == "stdout":
                        sys.stdout.write(ev_json + "\n")
                        sys.stdout.flush()
                    elif args.output == "file":
                        with open(state.log_path, "a", encoding="utf-8") as f:
                            f.write(ev_json + "\n")
                    elif args.output == "http":
                        engine._send_http_post(ev_dict)
                        
                # Sleep dynamic
                if engine.event_queue:
                    time.sleep(min(0.05, max(0.005, engine.event_queue[0]["run_at"] - time.time())))
                else:
                    time.sleep(0.01)
        except KeyboardInterrupt:
            sys.stderr.write("\n[!] Scenario execution interrupted.\n")
            sys.exit(1)
            
        if args.verbose:
            sys.stderr.write("[*] Single scenario completed. Exiting.\n")
        sys.exit(0)

    # Mode 2: Continuous execution loop
    try:
        engine.start()
        start_t = time.time()
        
        if args.verbose:
            sys.stderr.write("[*] Simulation running. Press Ctrl+C to terminate.\n")
            
        while state.running:
            # Check duration limit
            if args.duration and (time.time() - start_t >= args.duration):
                if args.verbose:
                    sys.stderr.write(f"[*] Duration limit of {args.duration} seconds reached. Exiting.\n")
                break
            time.sleep(0.5)
            
    except KeyboardInterrupt:
        if args.verbose:
            sys.stderr.write("\n[*] Terminating simulation engine...\n")
    finally:
        engine.stop()
        if args.verbose:
            sys.stderr.write(f"[*] Done. Generated {state.event_count} events total.\n")

if __name__ == "__main__":
    main()
