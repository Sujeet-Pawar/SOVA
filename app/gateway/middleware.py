"""Gateway Middleware - request/response processing utilities."""

import time
from typing import Optional
from app.request_processing.parser import HTTPRequest


class RateLimiter:
    """Simple in-memory rate limiter."""

    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: dict[str, list[float]] = {}

    def is_allowed(self, source_id: str) -> bool:
        """Check if a request from source_id is allowed."""
        now = time.time()
        window_start = now - self.window_seconds

        if source_id not in self._requests:
            self._requests[source_id] = []

        # Remove old requests outside the window
        self._requests[source_id] = [
            t for t in self._requests[source_id] if t > window_start
        ]

        if len(self._requests[source_id]) >= self.max_requests:
            return False

        self._requests[source_id].append(now)
        return True

    def get_request_count(self, source_id: str) -> int:
        """Get current request count for a source."""
        now = time.time()
        window_start = now - self.window_seconds

        if source_id not in self._requests:
            return 0

        return sum(1 for t in self._requests[source_id] if t > window_start)


class RequestContext:
    """Holds per-request processing context."""

    def __init__(self, request: HTTPRequest):
        self.request = request
        self.start_time = time.time()
        self.feature_vector = None
        self.rule_results = []
        self.anomaly_result = None
        self.behavioral_result = None
        self.security_signals = None
        self.action = "ALLOW"
        self.error: Optional[str] = None

    @property
    def latency_ms(self) -> float:
        """Calculate latency in milliseconds."""
        return round((time.time() - self.start_time) * 1000, 2)
