"""Behavioral Feature Extraction - session-based behavioral analysis."""

import time
from typing import Optional
from collections import defaultdict
from app.request_processing.parser import HTTPRequest


class BehavioralFeatureExtractor:
    """Extracts behavioral features from request patterns."""

    def __init__(self):
        # Per-session tracking
        self._session_requests: dict[str, list[dict]] = defaultdict(list)
        self._session_endpoints: dict[str, set] = defaultdict(set)
        self._session_failures: dict[str, int] = defaultdict(int)

    def extract(self, request: HTTPRequest) -> dict:
        """Extract behavioral features for a request."""
        session_id = request.session_id
        now = time.time()

        features = {}

        # Get session history (excluding current request, which we add below)
        session_history = self._session_requests[session_id]

        # Request frequency features (count includes this request = 1 for first)
        features["request_count_10s"] = self._count_recent(session_history, now, 10) + 1
        features["request_count_60s"] = self._count_recent(session_history, now, 60) + 1

        # Failed request count
        features["failed_request_count"] = self._session_failures.get(session_id, 0)

        # Endpoint diversity (this endpoint is included)
        self._session_endpoints[session_id].add(request.path)
        features["unique_endpoint_count"] = len(self._session_endpoints[session_id])

        # Repeated endpoint count (how many previous times this endpoint was hit)
        repeated = sum(
            1 for r in session_history if r.get("path") == request.path
        )
        features["repeated_endpoint_count"] = repeated

        # Session duration
        if session_history:
            first_time = session_history[0].get("timestamp", now)
            features["session_duration"] = now - first_time
        else:
            features["session_duration"] = 0

        # Requests per second rate
        duration = max(1, features["session_duration"])
        total_requests = len(session_history) + 1  # +1 for current
        features["request_rate"] = total_requests / duration

        # Record this request
        self._session_requests[session_id].append({
            "path": request.path,
            "method": request.method,
            "timestamp": now,
        })

        return features

    def record_failure(self, session_id: str):
        """Record a failed request for a session."""
        self._session_failures[session_id] += 1

    def get_feature_names(self) -> list[str]:
        """Return ordered list of feature names."""
        return [
            "request_count_10s",
            "request_count_60s",
            "failed_request_count",
            "unique_endpoint_count",
            "repeated_endpoint_count",
            "session_duration",
            "request_rate",
        ]

    def _count_recent(self, history: list[dict], now: float, seconds: int) -> int:
        """Count requests in the last N seconds."""
        cutoff = now - seconds
        return sum(1 for r in history if r.get("timestamp", 0) > cutoff)

    def clear_session(self, session_id: str):
        """Clear tracking data for a session."""
        self._session_requests.pop(session_id, None)
        self._session_endpoints.pop(session_id, None)
        self._session_failures.pop(session_id, None)
