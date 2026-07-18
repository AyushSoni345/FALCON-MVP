import sqlite3
import json
import os
from typing import Optional
from module6.interfaces import IDecisionTraceRepository
from module6.schemas.decision_trace import DecisionTrace

class SQLiteDecisionTraceRepository(IDecisionTraceRepository):
    def __init__(self, db_path: str):
        self.db_path = db_path
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS decision_traces (
                    trace_id TEXT PRIMARY KEY,
                    idempotency_key TEXT UNIQUE,
                    incident_id TEXT,
                    assessment_id TEXT,
                    timestamp TEXT,
                    config_version TEXT,
                    rule_version TEXT,
                    trace_json TEXT
                )
            ''')
            conn.commit()

    def save(self, trace: DecisionTrace) -> None:
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute('''
                INSERT OR REPLACE INTO decision_traces 
                (trace_id, idempotency_key, incident_id, assessment_id, timestamp, config_version, rule_version, trace_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                trace.trace_id,
                trace.idempotency_key,
                trace.incident_id,
                trace.input_assessment_id,
                trace.timestamp,
                trace.config_version,
                trace.rule_version,
                trace.model_dump_json()
            ))
            conn.commit()
        finally:
            conn.close()

    def get_by_id(self, trace_id: str) -> Optional[DecisionTrace]:
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.execute('SELECT trace_json FROM decision_traces WHERE trace_id = ?', (trace_id,))
            row = cursor.fetchone()
            if row:
                return DecisionTrace.model_validate_json(row[0])
        finally:
            conn.close()
        return None

    def get_by_idempotency_key(self, idempotency_key: str) -> Optional[DecisionTrace]:
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.execute('SELECT trace_json FROM decision_traces WHERE idempotency_key = ?', (idempotency_key,))
            row = cursor.fetchone()
            if row:
                return DecisionTrace.model_validate_json(row[0])
        finally:
            conn.close()
        return None
