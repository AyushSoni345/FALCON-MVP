import os
import sys
import time
import requests
import subprocess
import webbrowser
from dotenv import load_dotenv

def wait_for_service(name, url, timeout=30):
    print(f"Waiting for {name} to become healthy at {url}...")
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get(url, timeout=2)
            if r.status_code == 200:
                print(f"[OK] {name} is healthy.")
                return True
        except:
            pass
        time.sleep(2)
    print(f"[ERROR] {name} failed to become healthy within {timeout} seconds.")
    return False

def main():
    if not os.path.exists(".env"):
        print("[ERROR] .env file not found in the root directory.")
        sys.exit(1)
        
    load_dotenv()
    
    # Environment config
    services = [
        {
            "name": "Module 1 - Ingestion",
            "cwd": "backend/Ingestion",
            "module": "api.ingest:app",
            "port_env": "INGESTION_PORT",
            "health_path": "/health"
        },
        {
            "name": "Module 2 - Normalization",
            "cwd": "backend/Event Normalization",
            "module": "app.main:app",
            "port_env": "NORMALIZATION_PORT",
            "health_path": "/health"
        },
        {
            "name": "Module 3 - Knowledge Graph",
            "cwd": "backend/Knowledge Graph",
            "module": "src.main:app",
            "port_env": "GRAPH_PORT",
            "health_path": "/health"
        },
        {
            "name": "Module 4 - Correlation Engine",
            "cwd": "backend/AI-Driven Correlation and Reasoning Engine",
            "module": "app.main:app",
            "port_env": "CORRELATION_PORT",
            "health_path": "/health"
        },
        {
            "name": "Module 5 - AI Analytics",
            "cwd": "backend/Multi-Domain AI Analytics Layer",
            "module": "main:app",
            "port_env": "ANALYTICS_PORT",
            "health_path": "/health"
        },
        {
            "name": "Module 6 - Risk Scoring",
            "cwd": "backend/Context-Aware Risk Correlation & Scoring Engine",
            "module": "module6.api_main:app",
            "port_env": "RISK_PORT",
            "health_path": "/health"
        },
        {
            "name": "Module 7 - Threat Intelligence",
            "cwd": "backend/Explainable Threat Intelligence Engine/Module 7",
            "module": "app.main:app",
            "port_env": "EXPLAINABILITY_PORT",
            "health_path": "/health" 
        },
        {
            "name": "Module 8 - Response Engine",
            "cwd": "backend/Decision , Response and Continous Learning Engine",
            "module": "module_8.api_main:app",
            "port_env": "RESPONSE_PORT",
            "health_path": "/health"
        },
        {
            "name": "Module 9 - Dashboard",
            "cwd": "frontend/Dashboard/Module 9",
            "module": "app.main:app",
            "port_env": "DASHBOARD_PORT",
            "health_path": "/health"
        }
    ]

    processes = []
    
    try:
        root_dir = os.path.dirname(os.path.abspath(__file__))
        for svc in services:
            port = os.environ.get(svc["port_env"])
            if not port:
                print(f"[ERROR] {svc['port_env']} is not defined in .env")
                sys.exit(1)
            
            svc_cwd = os.path.join(root_dir, svc["cwd"])
            
            cmd = [sys.executable, "-m", "uvicorn", svc["module"], "--host", "0.0.0.0", "--port", str(port)]
            
            print(f"Starting {svc['name']} on port {port}...")
            # Run from the module directory and append the root dir to PYTHONPATH
            env = os.environ.copy()
            backend_dir = os.path.join(root_dir, "backend")
            env["PYTHONPATH"] = os.pathsep.join([root_dir, backend_dir, svc_cwd])
            
            p = subprocess.Popen(cmd, cwd=svc_cwd, env=env)
            processes.append(p)
            
            url = f"http://127.0.0.1:{port}{svc['health_path']}"
            if not wait_for_service(svc["name"], url, timeout=60):
                print(f"[CRITICAL] Stopping all services because {svc['name']} failed to start.")
                sys.exit(1)
                
        print("\n==============================================")
        print("FALCON Platform MVP Successfully Started!")
        dashboard_port = os.environ.get('DASHBOARD_PORT')
        dashboard_url = f"http://127.0.0.1:{dashboard_port}/"
        print(f"Dashboard available at: {dashboard_url}")
        print("==============================================\n")
        
        if wait_for_service("Module 9 - Dashboard (UI)", dashboard_url, timeout=30):
            print("[INFO] Launching Dashboard in the default browser...")
            webbrowser.open(dashboard_url)
        else:
            print("[ERROR] Dashboard UI did not become ready in time. Please open the URL manually.")

        print("Starting E2E Event Forwarder Daemon...")
        forwarder_cmd = [sys.executable, "e2e_forwarder.py"]
        fwd_p = subprocess.Popen(forwarder_cmd, cwd=root_dir, env=os.environ.copy())
        processes.append(fwd_p)

        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nShutting down FALCON services...")
    finally:
        for p in processes:
            p.terminate()
        for p in processes:
            p.wait()
        print("All services stopped.")

if __name__ == "__main__":
    main()
