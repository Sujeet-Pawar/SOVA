"""HTTP Request Parser - converts raw HTTP into internal representation."""

import uuid
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field
from urllib.parse import urlparse, parse_qs


class HTTPRequest(BaseModel):
    """Internal HTTP request representation.

    Does not store raw sensitive data permanently.
    Body is represented by metadata only.
    """
    request_id: str = Field(default_factory=lambda: f"REQ-{uuid.uuid4().hex[:8].upper()}")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    source_id: str = "UNKNOWN"
    method: str = "GET"
    path: str = "/"
    query: dict = Field(default_factory=dict)
    query_string: str = ""
    headers: dict = Field(default_factory=dict)
    body_metadata: dict = Field(default_factory=dict)
    body_fields: list[str] = Field(default_factory=list)
    body_size: int = 0
    session_id: str = "UNKNOWN"
    content_type: str = ""
    user_agent: str = ""
    remote_addr: str = ""
    url_length: int = 0
    path_length: int = 0
    query_length: int = 0

    def compute_lengths(self):
        """Compute derived length fields."""
        self.url_length = len(self.path) + len(self.query_string)
        self.path_length = len(self.path)
        self.query_length = len(self.query_string)


class RequestParser:
    """Parses incoming HTTP requests into HTTPRequest model."""

    SENSITIVE_FIELDS = {"password", "secret", "token", "api_key", "apikey", "auth", "credential"}

    def parse(
        self,
        method: str,
        path: str,
        headers: dict,
        query_string: str = "",
        body: bytes = b"",
        source_id: str = "UNKNOWN",
        session_id: str = "UNKNOWN",
        remote_addr: str = "",
    ) -> HTTPRequest:
        """Parse raw HTTP request data into HTTPRequest model."""
        query = parse_qs(query_string) if query_string else {}

        body_fields, body_size = self._analyze_body(body, headers)
        content_type = headers.get("content-type", "")
        user_agent = headers.get("user-agent", "")

        request = HTTPRequest(
            source_id=source_id,
            method=method.upper(),
            path=path,
            query=query,
            query_string=query_string,
            headers=self._filter_headers(headers),
            body_fields=body_fields,
            body_size=body_size,
            session_id=session_id,
            content_type=content_type,
            user_agent=user_agent,
            remote_addr=remote_addr,
        )
        request.compute_lengths()
        return request

    def _analyze_body(self, body: bytes, headers: dict) -> tuple[list[str], int]:
        """Extract body metadata without storing sensitive values."""
        body_size = len(body)
        body_fields = []

        if body_size == 0:
            return body_fields, body_size

        content_type = headers.get("content-type", "")

        if "application/x-www-form-urlencoded" in content_type:
            try:
                decoded = body.decode("utf-8", errors="replace")
                pairs = decoded.split("&")
                for pair in pairs:
                    if "=" in pair:
                        key = pair.split("=")[0]
                        body_fields.append(key)
            except Exception:
                pass
        elif "application/json" in content_type:
            try:
                import json
                data = json.loads(body)
                if isinstance(data, dict):
                    body_fields = list(data.keys())
            except Exception:
                pass

        return body_fields, body_size

    def _filter_headers(self, headers: dict) -> dict:
        """Return safe headers (no authorization tokens)."""
        safe = {}
        for key, value in headers.items():
            lower_key = key.lower()
            if any(s in lower_key for s in self.SENSITIVE_FIELDS):
                safe[key] = "[REDACTED]"
            else:
                safe[key] = value
        return safe
