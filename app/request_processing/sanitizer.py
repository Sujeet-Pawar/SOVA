"""Request Sanitizer - cleans and validates request data."""

import re
from typing import Optional
from app.request_processing.parser import HTTPRequest


class RequestSanitizer:
    """Sanitizes HTTP requests for safe processing and storage."""

    # Characters to strip from various fields
    CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

    # Maximum field lengths
    MAX_PATH_LENGTH = 2048
    MAX_QUERY_LENGTH = 4096
    MAX_HEADER_SIZE = 8192
    MAX_BODY_SIZE = 10 * 1024 * 1024  # 10MB

    def sanitize(self, request: HTTPRequest) -> HTTPRequest:
        """Apply sanitization to an HTTPRequest."""
        request.path = self.sanitize_path(request.path)
        request.query_string = self.sanitize_query_string(request.query_string)
        request.headers = self.sanitize_headers(request.headers)
        request.compute_lengths()
        return request

    def sanitize_path(self, path: str) -> str:
        """Sanitize URL path."""
        if not path:
            return "/"

        # Remove control characters
        path = self.CONTROL_CHARS.sub("", path)

        # Limit length
        if len(path) > self.MAX_PATH_LENGTH:
            path = path[:self.MAX_PATH_LENGTH]

        # Normalize path separators
        path = re.sub(r"/+", "/", path)

        return path

    def sanitize_query_string(self, query: str) -> str:
        """Sanitize query string."""
        if not query:
            return ""

        # Remove control characters
        query = self.CONTROL_CHARS.sub("", query)

        # Limit length
        if len(query) > self.MAX_QUERY_LENGTH:
            query = query[:self.MAX_QUERY_LENGTH]

        return query

    def sanitize_headers(self, headers: dict) -> dict:
        """Sanitize HTTP headers."""
        sanitized = {}
        for key, value in headers.items():
            # Remove control characters from header values
            clean_key = self.CONTROL_CHARS.sub("", key)
            clean_value = self.CONTROL_CHARS.sub("", str(value))
            sanitized[clean_key] = clean_value
        return sanitized

    def is_valid(self, request: HTTPRequest) -> tuple[bool, Optional[str]]:
        """Validate request is well-formed."""
        if not request.method:
            return False, "Missing HTTP method"

        if not request.path:
            return False, "Missing request path"

        if len(request.path) > self.MAX_PATH_LENGTH:
            return False, f"Path exceeds maximum length of {self.MAX_PATH_LENGTH}"

        valid_methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
        if request.method not in valid_methods:
            return False, f"Invalid HTTP method: {request.method}"

        return True, None

    def compute_special_char_ratio(self, text: str) -> float:
        """Calculate ratio of special characters in text."""
        if not text:
            return 0.0

        special = sum(1 for c in text if not c.isalnum() and not c.isspace())
        return special / len(text)

    def compute_digit_ratio(self, text: str) -> float:
        """Calculate ratio of digits in text."""
        if not text:
            return 0.0

        digits = sum(1 for c in text if c.isdigit())
        return digits / len(text)
