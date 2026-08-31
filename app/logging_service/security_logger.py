"""Security Logger - logs security events to console and SQLite."""

import sqlite3
import os
from datetime import datetime
from typing import Optional
from pathlib import Path
from app.request_processing.parser import HTTPRequest
from app.detection.common.models import SecuritySignals


class SecurityLogger:
    """Logs security events to console and SQLite database."""

    def __init__(self, config: dict = None):
        config = config or {}
        self.db_path = config.get("database", "data/sova_waf.db")
        self.console_output = config.get("security_events", True)

        # Ensure directory exists
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

        # Initialize database
        self._init_db()

    def _init_db(self):
        """Initialize the SQLite database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                request_id TEXT NOT NULL,
                source_id TEXT,
                endpoint TEXT,
                method TEXT,
                threat_type TEXT,
                rule_score REAL DEFAULT 0.0,
                anomaly_score REAL DEFAULT 0.0,
                behavior_score REAL DEFAULT 0.0,
                action TEXT NOT NULL,
                reason TEXT,
                details TEXT
            )
        """)
        conn.commit()
        conn.close()

    def log_event(self, request: HTTPRequest, signals: SecuritySignals):
        """Log a security event."""
        # Determine threat type
        threat_type = "NONE"
        if signals.detected_threats:
            threat_type = signals.detected_threats[0].threat_type.value

        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "request_id": request.request_id,
            "source_id": request.source_id,
            "endpoint": request.path,
            "method": request.method,
            "threat_type": threat_type,
            "rule_score": signals.known_threat_score,
            "anomaly_score": signals.anomaly_score,
            "behavior_score": signals.behavior_score,
            "action": signals.action,
            "reason": "; ".join(signals.explanations) if signals.explanations else "No specific reason",
        }

        # Store in database
        self._store_event(event)

        # Print to console
        if self.console_output:
            self._print_event(event)

    def _store_event(self, event: dict):
        """Store security event in SQLite."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO security_events
                (timestamp, request_id, source_id, endpoint, method, threat_type,
                 rule_score, anomaly_score, behavior_score, action, reason)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event["timestamp"],
                event["request_id"],
                event["source_id"],
                event["endpoint"],
                event["method"],
                event["threat_type"],
                event["rule_score"],
                event["anomaly_score"],
                event["behavior_score"],
                event["action"],
                event["reason"],
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[SECURITY LOGGER] Database error: {e}")

    def _print_event(self, event: dict):
        """Print security event to console."""
        print("\n" + "=" * 60)
        print("SECURITY EVENT")
        print("=" * 60)
        print(f"Timestamp:       {event['timestamp']}")
        print(f"Request ID:      {event['request_id']}")
        print(f"Source:          {event['source_id']}")
        print(f"Endpoint:        {event['method']} {event['endpoint']}")
        print(f"Threat:          {event['threat_type']}")
        print(f"Rule Score:      {event['rule_score']:.3f}")
        print(f"Anomaly Score:   {event['anomaly_score']:.3f}")
        print(f"Behavior Score:  {event['behavior_score']:.3f}")
        print(f"Action:          {event['action']}")
        print(f"Reason:          {event['reason']}")
        print("=" * 60 + "\n")

    def get_events(self, limit: int = 100) -> list[dict]:
        """Get recent security events from database."""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM security_events ORDER BY id DESC LIMIT ?",
                (limit,)
            )
            events = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return events
        except Exception as e:
            print(f"[SECURITY LOGGER] Database error: {e}")
            return []

    def get_event_count(self) -> int:
        """Get total number of security events."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM security_events")
            count = cursor.fetchone()[0]
            conn.close()
            return count
        except Exception as e:
            return 0
