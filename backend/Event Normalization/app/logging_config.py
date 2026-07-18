import logging
import json
import sys
from datetime import datetime, timezone
from typing import Optional

class DevFormatter(logging.Formatter):
    """Formats logs for clear terminal visualization in development mode."""
    def format(self, record):
        level = record.levelname
        msg = record.getMessage()
        stage = getattr(record, "processing_stage", None)
        status = getattr(record, "status", "N/A")
        event_uuid = getattr(record, "event_uuid", "N/A")
        correlation_id = getattr(record, "correlation_id", "N/A")
        duration = getattr(record, "duration", None)
        
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        dur_str = f" ({duration:.2f} ms)" if duration is not None else ""
        
        # Build clean console line
        log_str = f"[{level}] [{timestamp}] [uuid:{event_uuid}] [corr:{correlation_id}] [{stage}] [{status}]{dur_str} {msg}"
        
        # Prepend a transition arrow if transitioning in pipeline
        if stage and stage != "request_received":
            return f"->\n{log_str}"
        return log_str

class JsonFormatter(logging.Formatter):
    """Enforces standard JSON serialization with full extra attributes included."""
    def format(self, record):
        log_data = {
            "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
            "level": record.levelname,
            "message": record.getMessage(),
            "module": record.module,
            "filename": record.filename,
            "lineno": record.lineno,
        }
        # Add all extra attributes
        for key, value in record.__dict__.items():
            if key not in [
                "args", "asctime", "created", "exc_info", "exc_text", "filename",
                "funcName", "levelname", "levelno", "lineno", "module", "msecs",
                "message", "msg", "name", "pathname", "process", "processName",
                "relativeCreated", "stack_info", "thread", "threadName"
            ]:
                log_data[key] = value
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_data)

def setup_logging():
    from app.config import settings
    
    logger = logging.getLogger("falcon")
    
    # Configure level
    level_name = settings.log_level.upper()
    level = getattr(logging, level_name, logging.INFO)
    logger.setLevel(level)
    
    if logger.handlers:
        logger.handlers.clear()
        
    handler = logging.StreamHandler(sys.stdout)
    
    if settings.env == "development":
        handler.setFormatter(DevFormatter())
    else:
        handler.setFormatter(JsonFormatter())
        
    logger.addHandler(handler)
    
    # Keep Uvicorn access logging ENABLED at INFO level
    logging.getLogger("uvicorn.access").setLevel(logging.INFO)
    logging.getLogger("uvicorn.error").setLevel(logging.INFO)
    
    return logger

logger = setup_logging()

def log_pipeline(
    level: int,
    message: str,
    stage: str,
    status: str,
    event_uuid: Optional[str] = None,
    correlation_id: Optional[str] = None,
    duration: Optional[float] = None,
    parser_name: Optional[str] = None
):
    extra = {
        "event_uuid": event_uuid,
        "correlation_id": correlation_id,
        "processing_stage": stage,
        "status": status
    }
    if duration is not None:
        extra["duration"] = duration
    if parser_name:
        extra["parser_name"] = parser_name
        
    logger.log(level, message, extra=extra)
