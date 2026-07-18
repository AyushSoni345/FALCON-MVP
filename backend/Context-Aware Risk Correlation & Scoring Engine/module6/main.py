import os
import json
import argparse
from typing import Dict, Any

from module6.config.manager import ConfigurationManager
from module6.repositories.decision_trace_repo import SQLiteDecisionTraceRepository
from module6.audit_logging.audit_logger import AuditLogger
from module6.metrics.collector import MetricsCollector
from module6.pipeline import Module6Pipeline
from module6.schemas.domain_ai_assessment import DomainAIAssessment
from module6.exceptions import ValidationException

def setup_app(config_dir: str, storage_dir: str):
    config_manager = ConfigurationManager(config_dir)
    config_manager.load_and_validate_configs()
    
    trace_repo = SQLiteDecisionTraceRepository(os.path.join(storage_dir, "module6_audit.db"))
    audit_logger = AuditLogger(os.path.join(storage_dir, "audit_logs"))
    metrics_collector = MetricsCollector(os.path.join(storage_dir, "metrics"))
    
    pipeline = Module6Pipeline(config_manager, trace_repo, audit_logger, metrics_collector)
    return pipeline, metrics_collector

def run_pipeline(pipeline: Module6Pipeline, input_json_path: str, context_json_path: str = None) -> None:
    with open(input_json_path, 'r', encoding='utf-8') as f:
        input_data = json.load(f)
        
    try:
        assessment = DomainAIAssessment.model_validate(input_data)
    except Exception as e:
        raise ValidationException(f"Input validation failed: {str(e)}")

    external_context = {}
    if context_json_path and os.path.exists(context_json_path):
        with open(context_json_path, 'r', encoding='utf-8') as f:
            external_context = json.load(f)

    result = pipeline.process(assessment, external_context)
    
    print("\n--- Unified Risk Assessment ---")
    print(result.unified_risk_assessment.model_dump_json(indent=2, by_alias=True))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Module 6 Execution Entrypoint")
    parser.add_argument("--config", type=str, default="module6/config", help="Config directory")
    parser.add_argument("--storage", type=str, default="storage", help="Storage directory")
    parser.add_argument("--input", type=str, required=True, help="Input DomainAIAssessment JSON")
    parser.add_argument("--context", type=str, help="External Context JSON")
    args = parser.parse_args()

    pipeline, metrics = setup_app(args.config, args.storage)
    run_pipeline(pipeline, args.input, args.context)
    metrics.dump_metrics()
