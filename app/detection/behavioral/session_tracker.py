"""Session Tracker - tracks request history per session/source."""

import time
from collections import defaultdict
from typing import Optional
from app.request_processing.parser import HTTPRequest


class SessionTracker:
    """Tracks per-session request history for behavioral analysis."""

    def __init__(self, session_ttl: int = 300):
        """
        Args:
            session_ttl: Session time-to-live in seconds
        """
        self.session_ttl = session_ttl

        # Per-session data
        self._sessions: dict[str, dict] = defaultdict(lambda: {
            "requests": [],
            "endpoints": set(),
            "methods": set(),
            "first_seen": time.time(),
            "last_seen": time.time(),
            "failed_count": 0,
            "success_count": 0,
            "unique_ips": set(),
        })

    def record_request(self, request: HTTPRequest):
        """Record a request in the session tracker."""
        session_id = request.session_id
        now = time.time()

        session = self._sessions[session_id]
        session["requests"].append({
            "path": request.path,
            "method": request.method,
            "timestamp": now,
            "source_id": request.source_id,
        })
        session["endpoints"].add(request.path)
        session["methods"].add(request.method)
        session["last_seen"] = now
        if request.remote_addr:
            session["unique_ips"].add(request.remote_addr)

    def record_failure(self, session_id: str):
        """Record a failed request for a session."""
        if session_id in self._sessions:
            self._sessions[session_id]["failed_count"] += 1

    def record_success(self, session_id: str):
        """Record a successful request for a session."""
        if session_id in self._sessions:
            self._sessions[session_id]["success_count"] += 1

    def get_session_stats(self, session_id: str) -> dict:
        """Get statistics for a session."""
        if session_id not in self._sessions:
            return self._empty_stats()

        session = self._sessions[session_id]
        now = time.time()

        # Filter recent requests
        recent_10s = [
            r for r in session["requests"]
            if now - r["timestamp"] <= 10
        ]
        recent_60s = [
            r for r in session["requests"]
            if now - r["timestamp"] <= 60
        ]

        # Calculate request rate
        duration = max(1, now - session["first_seen"])
        total_requests = len(session["requests"])
        request_rate = total_requests / duration

        # Endpoint diversity
        endpoint_counts = defaultdict(int)
        for r in session["requests"]:
            endpoint_counts[r["path"]] += 1

        most_common = max(endpoint_counts.values()) if endpoint_counts else 0
        endpoint_diversity = len(session["endpoints"]) / max(1, len(session["requests"]))

        return {
            "session_id": session_id,
            "total_requests": total_requests,
            "request_count_10s": len(recent_10s),
            "request_count_60s": len(recent_60s),
            "unique_endpoints": len(session["endpoints"]),
            "unique_methods": len(session["methods"]),
            "endpoint_diversity": endpoint_diversity,
            "max_endpoint_hits": most_common,
            "request_rate": request_rate,
            "failed_count": session["failed_count"],
            "success_count": session["success_count"],
            "failure_rate": session["failed_count"] / max(1, total_requests),
            "session_duration": duration,
            "unique_ips": len(session["unique_ips"]),
            "last_seen": session["last_seen"],
        }

    def _empty_stats(self) -> dict:
        """Return empty session statistics."""
        return {
            "session_id": "UNKNOWN",
            "total_requests": 0,
            "request_count_10s": 0,
            "request_count_60s": 0,
            "unique_endpoints": 0,
            "unique_methods": 0,
            "endpoint_diversity": 0.0,
            "max_endpoint_hits": 0,
            "request_rate": 0.0,
            "failed_count": 0,
            "success_count": 0,
            "failure_rate": 0.0,
            "session_duration": 0.0,
            "unique_ips": 0,
            "last_seen": 0.0,
        }

    def clear_expired(self):
        """Remove expired sessions."""
        now = time.time()
        expired = [
            sid for sid, session in self._sessions.items()
            if now - session["last_seen"] > self.session_ttl
        ]
        for sid in expired:
            del self._sessions[sid]
