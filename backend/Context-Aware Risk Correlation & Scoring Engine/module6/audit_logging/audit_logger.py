import logging
import json
import os
from datetime import datetime
from typing import Any, Dict

class AuditLogger:
    def __init__(self, log_dir: str):
        self.log_dir = log_dir
        os.makedirs(self.log_dir, exist_ok=True)
        self.log_file = os.path.join(self.log_dir, f"audit_{datetime.utcnow().strftime('%Y%m%d')}.jsonl")
        
        # Setup specific audit logger
        self.logger = logging.getLogger("audit_logger")
        self.logger.setLevel(logging.INFO)
        
        # Prevent handler accumulation and dynamically update path if log_dir changes
        for h in list(self.logger.handlers):
            if isinstance(h, logging.FileHandler):
                h.close()
                self.logger.removeHandler(h)
                
        handler = logging.FileHandler(self.log_file, encoding='utf-8')
        handler.setFormatter(logging.Formatter('%(message)s'))
        self.logger.addHandler(handler)

    def log_decision(self, trace_id: str, idempotency_key: str, incident_id: str, assessment_id: str, metadata: Dict[str, Any]):
        audit_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "trace_id": trace_id,
            "idempotency_key": idempotency_key,
            "incident_id": incident_id,
            "assessment_id": assessment_id,
            "metadata": metadata
        }
        self.logger.info(json.dumps(audit_entry))
