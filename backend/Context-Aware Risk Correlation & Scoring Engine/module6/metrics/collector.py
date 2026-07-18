from typing import Dict, Any, List
from collections import Counter, deque
import time
import json
import os

class MetricsCollector:
    def __init__(self, metrics_dir: str):
        self.metrics_dir = metrics_dir
        os.makedirs(self.metrics_dir, exist_ok=True)
        self.processing_latency_ms: deque = deque(maxlen=1000)
        self.validation_failures_total: int = 0
        self.suppressed_alerts_total: int = 0
        self.priority_distribution = Counter()
        self.confidence_sum: float = 0.0
        self.completeness_sum: float = 0.0
        self.processed_count: int = 0
        self.rule_hit_count = Counter()

    def record_latency(self, latency_ms: float):
        self.processing_latency_ms.append(latency_ms)

    def record_validation_failure(self):
        self.validation_failures_total += 1

    def record_suppression(self, rule_id: str):
        self.suppressed_alerts_total += 1
        self.rule_hit_count[rule_id] += 1

    def record_processing(self, priority: str, confidence: float, completeness: float):
        self.priority_distribution[priority] += 1
        self.confidence_sum += confidence
        self.completeness_sum += completeness
        self.processed_count += 1

    def dump_metrics(self) -> Dict[str, Any]:
        avg_conf = (self.confidence_sum / self.processed_count) if self.processed_count > 0 else 0.0
        avg_comp = (self.completeness_sum / self.processed_count) if self.processed_count > 0 else 0.0
        avg_lat = (sum(self.processing_latency_ms) / len(self.processing_latency_ms)) if self.processing_latency_ms else 0.0
        
        metrics = {
            "processed_count": self.processed_count,
            "average_latency_ms": avg_lat,
            "validation_failures": self.validation_failures_total,
            "suppressed_alerts": self.suppressed_alerts_total,
            "priority_distribution": dict(self.priority_distribution),
            "average_confidence": avg_conf,
            "average_completeness": avg_comp,
            "rule_hit_count": dict(self.rule_hit_count)
        }
        filepath = os.path.join(self.metrics_dir, "metrics.json")
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(metrics, f, indent=2)
        return metrics
