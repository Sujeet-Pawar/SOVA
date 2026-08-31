"""Request Logger - logs HTTP request/response information."""

import time
from datetime import datetime
from typing import Optional
from app.request_processing.parser import HTTPRequest


class RequestLogger:
    """Logs request and response information."""

    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self._log_buffer: list[dict] = []

    def log_request(self, request: HTTPRequest):
        """Log an incoming request."""
        if not self.enabled:
            return

        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "request_id": request.request_id,
            "source_id": request.source_id,
            "method": request.method,
            "path": request.path,
            "query_string": request.query_string,
            "session_id": request.session_id,
            "user_agent": request.user_agent[:100] if request.user_agent else "",
            "content_type": request.content_type,
            "body_size": request.body_size,
        }

        self._log_buffer.append(entry)
        self._print_request(entry)

    def log_response(self, request: HTTPRequest, status_code: int, latency_ms: float):
        """Log a response."""
        if not self.enabled:
            return

        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "request_id": request.request_id,
            "method": request.method,
            "path": request.path,
            "status_code": status_code,
            "latency_ms": latency_ms,
        }

        self._print_response(entry)

    def get_logs(self) -> list[dict]:
        """Get all buffered logs."""
        return self._log_buffer.copy()

    def clear(self):
        """Clear the log buffer."""
        self._log_buffer.clear()

    def _print_request(self, entry: dict):
        """Print request log to console."""
        print(
            f"[REQUEST] {entry['request_id']} "
            f"{entry['method']} {entry['path']} "
            f"from {entry['source_id']}"
        )

    def _print_response(self, entry: dict):
        """Print response log to console."""
        print(
            f"[RESPONSE] {entry['request_id']} "
            f"STATUS {entry['status_code']} "
            f"LATENCY {entry['latency_ms']}ms"
        )
