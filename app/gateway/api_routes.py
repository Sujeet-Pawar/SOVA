"""API Routes - REST endpoints for the React frontend."""

import sys
import time
import json
import sqlite3
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app.request_processing.parser import RequestParser
from app.request_processing.normalizer import RequestNormalizer
from app.request_processing.sanitizer import RequestSanitizer
from app.feature_engine.pipeline import FeaturePipeline
from app.detection.rules.base import RuleEngine
from app.detection.anomaly.detector import AnomalyDetector
from app.detection.behavioral.detector import BehavioralDetector
from app.detection.common.models import SecuritySignals, ThreatType
from app.enforcement.block import EnforcementEngine
import yaml


def load_config() -> dict:
    config_path = PROJECT_ROOT / "config" / "config.yaml"
    if config_path.exists():
        with open(config_path) as f:
            return yaml.safe_load(f)
    return {}


router = APIRouter(prefix="/api", tags=["frontend"])

# Initialize components (shared with gateway)
parser = RequestParser()
normalizer = RequestNormalizer()
sanitizer = RequestSanitizer()
feature_pipeline = FeaturePipeline()
rule_engine = RuleEngine()
anomaly_detector = AnomalyDetector()
behavioral_detector = BehavioralDetector()
config = load_config()
enforcement_engine = EnforcementEngine(config.get("enforcement", {}))

# Per-source tracking for stats
_stats = {
    "total_requests": 0,
    "allowed": 0,
    "flagged": 0,
    "blocked": 0,
    "timeline": [],  # [{timestamp, action, scores}]
    "threat_counts": defaultdict(int),
    "score_history": [],
}

DB_PATH = config.get("logging", {}).get("database", "data/sova_waf.db")


class TestRequest(BaseModel):
    method: str = "GET"
    path: str = "/"
    query_string: str = ""
    body: str = ""
    source_id: str = "FRONTEND-TEST"


@router.get("/stats")
async def get_stats():
    """Get overall WAF statistics."""
    return {
        "total_requests": _stats["total_requests"],
        "allowed": _stats["allowed"],
        "flagged": _stats["flagged"],
        "blocked": _stats["blocked"],
        "threat_counts": dict(_stats["threat_counts"]),
        "detection_rate": (
            (_stats["blocked"] + _stats["flagged"]) / max(1, _stats["total_requests"]) * 100
        ),
    }


@router.get("/timeline")
async def get_timeline():
    """Get recent request timeline for charts."""
    # Return last 50 entries
    return {"timeline": _stats["timeline"][-50:]}


@router.get("/score-history")
async def get_score_history():
    """Get anomaly score history for chart."""
    return {"scores": _stats["score_history"][-100:]}


@router.get("/events")
async def get_events(limit: int = 50):
    """Get security events from the database."""
    events = []
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM security_events ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        events = [dict(row) for row in cursor.fetchall()]
        conn.close()
    except Exception:
        pass
    return {"events": events}


@router.get("/events/stats")
async def get_event_stats():
    """Get event statistics from the database."""
    stats = {
        "total_events": 0,
        "by_threat_type": {},
        "by_action": {},
        "by_hour": {},
        "avg_scores": {"rule": 0, "anomaly": 0, "behavior": 0},
    }
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM security_events")
        stats["total_events"] = cursor.fetchone()[0]

        cursor.execute(
            "SELECT threat_type, COUNT(*) FROM security_events GROUP BY threat_type"
        )
        stats["by_threat_type"] = {row[0]: row[1] for row in cursor.fetchall()}

        cursor.execute(
            "SELECT action, COUNT(*) FROM security_events GROUP BY action"
        )
        stats["by_action"] = {row[0]: row[1] for row in cursor.fetchall()}

        cursor.execute(
            """SELECT
                CAST(substr(timestamp, 12, 2) AS INTEGER) as hour,
                COUNT(*) as cnt
            FROM security_events
            GROUP BY hour ORDER BY hour"""
        )
        stats["by_hour"] = {str(row[0]): row[1] for row in cursor.fetchall()}

        cursor.execute(
            """SELECT
                AVG(rule_score), AVG(anomaly_score), AVG(behavior_score)
            FROM security_events"""
        )
        row = cursor.fetchone()
        if row and row[0] is not None:
            stats["avg_scores"] = {
                "rule": round(row[0], 3),
                "anomaly": round(row[1], 3),
                "behavior": round(row[2], 3),
            }

        conn.close()
    except Exception:
        pass
    return stats


@router.post("/test-request")
async def test_request(req: TestRequest):
    """Send a request through the full detection pipeline and return results."""
    start_time = time.time()

    # Parse
    http_request = parser.parse(
        method=req.method,
        path=req.path,
        headers={"host": "127.0.0.1", "user-agent": "SOVA-Frontend/1.0"},
        query_string=req.query_string,
        body=req.body.encode() if req.body else b"",
        source_id=req.source_id,
        session_id=f"FRONTEND-{req.source_id}",
    )

    # Normalize
    http_request.path = normalizer.normalize_path(http_request.path)
    http_request.method = normalizer.normalize_method(http_request.method)
    http_request.headers = normalizer.normalize_headers(http_request.headers)

    # Sanitize
    http_request = sanitizer.sanitize(http_request)

    # Feature extraction
    feature_vector = feature_pipeline.extract(http_request)

    # Rule detection
    rule_results = rule_engine.analyze(http_request)
    max_rule_score = max((r.score for r in rule_results), default=0)

    # Anomaly detection
    anomaly_result = anomaly_detector.detect(feature_vector)

    # Behavioral detection
    behavioral_result = behavioral_detector.detect(http_request)

    # Build signals
    signals = SecuritySignals(
        known_threat_score=max_rule_score,
        anomaly_score=anomaly_result.anomaly_score if anomaly_result else 0,
        behavior_score=behavioral_result.behavior_score if behavioral_result else 0,
        detected_threats=[r for r in rule_results if r.score > 0],
    )

    # Enforcement
    action = enforcement_engine.decide(signals)
    signals.action = action

    latency_ms = round((time.time() - start_time) * 1000, 2)

    # Update stats
    _stats["total_requests"] += 1
    if action == "ALLOW":
        _stats["allowed"] += 1
    elif action == "FLAG":
        _stats["flagged"] += 1
    elif action == "BLOCK":
        _stats["blocked"] += 1

    # Record timeline entry
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "method": req.method,
        "path": req.path,
        "action": action,
        "rule_score": round(max_rule_score, 3),
        "anomaly_score": round(anomaly_result.anomaly_score, 3) if anomaly_result else 0,
        "behavior_score": round(behavioral_result.behavior_score, 3) if behavioral_result else 0,
        "latency_ms": latency_ms,
    }
    _stats["timeline"].append(entry)
    _stats["score_history"].append(entry)

    for r in rule_results:
        if r.threat_type != ThreatType.NONE:
            _stats["threat_counts"][r.threat_type.value] += 1

    # Build rule details
    rule_details = [
        {
            "detector": r.detector,
            "threat_type": r.threat_type.value,
            "score": round(r.score, 3),
            "confidence": round(r.confidence, 3),
            "reason": r.reason,
            "evidence": r.evidence,
        }
        for r in rule_results
    ]

    return {
        "request": {
            "request_id": http_request.request_id,
            "method": http_request.method,
            "path": http_request.path,
            "query_string": http_request.query_string,
        },
        "features": {
            "url_length": feature_vector.features.get("url_length", 0),
            "special_char_ratio": round(feature_vector.features.get("special_char_ratio", 0), 3),
            "entropy": round(feature_vector.features.get("entropy", 0), 3),
            "parameter_count": feature_vector.features.get("parameter_count", 0),
            "encoding_ratio": round(feature_vector.features.get("encoding_ratio", 0), 3),
        },
        "detection": {
            "rule_results": rule_details,
            "max_rule_score": round(max_rule_score, 3),
            "anomaly_result": {
                "anomaly_score": round(anomaly_result.anomaly_score, 3),
                "classification": anomaly_result.classification,
                "reason": anomaly_result.reason,
            } if anomaly_result else None,
            "behavioral_result": {
                "behavior_score": round(behavioral_result.behavior_score, 3),
                "classification": behavioral_result.classification,
                "reason": behavioral_result.reason,
            } if behavioral_result else None,
        },
        "signals": {
            "known_threat_score": round(signals.known_threat_score, 3),
            "anomaly_score": round(signals.anomaly_score, 3),
            "behavior_score": round(signals.behavior_score, 3),
            "action": action,
            "explanations": signals.explanations,
        },
        "latency_ms": latency_ms,
    }
