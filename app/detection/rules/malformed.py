"""Malformed Request Detector - detects protocol-violating requests."""

import re
from app.request_processing.parser import HTTPRequest
from app.detection.common.models import DetectionResult, ThreatType
from app.detection.rules.base import BaseDetector


class MalformedRequestDetector(BaseDetector):
    """Detects malformed HTTP requests that may indicate attacks."""

    name = "MalformedRequestDetector"
    threat_type = ThreatType.MALFORMED

    # Valid HTTP methods
    VALID_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"}

    def analyze(self, request: HTTPRequest) -> DetectionResult:
        """Analyze request for malformed characteristics."""
        evidence = []
        score = 0.0

        # Check HTTP method validity
        if request.method not in self.VALID_METHODS:
            evidence.append(f"Invalid HTTP method: {request.method}")
            score = max(score, 0.9)

        # Check for null bytes in path
        if "\x00" in request.path:
            evidence.append("Null byte in request path")
            score = max(score, 0.95)

        # Check for excessive path length
        if len(request.path) > 2048:
            evidence.append(f"Excessively long path: {len(request.path)} chars")
            score = max(score, 0.5)

        # Check for excessive header count
        if len(request.headers) > 100:
            evidence.append(f"Excessive headers: {len(request.headers)}")
            score = max(score, 0.4)

        # Check for missing required headers
        if not request.headers.get("host") and not request.headers.get("Host"):
            evidence.append("Missing Host header")
            score = max(score, 0.3)

        # Check for control characters in path
        control_chars = re.findall(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", request.path)
        if control_chars:
            evidence.append(f"Control characters in path: {len(control_chars)} found")
            score = max(score, 0.8)

        # Check for control characters in query
        control_in_query = re.findall(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", request.query_string)
        if control_in_query:
            evidence.append(f"Control characters in query: {len(control_in_query)} found")
            score = max(score, 0.7)

        # Check for oversized body
        if request.body_size > 10 * 1024 * 1024:  # 10MB
            evidence.append(f"Oversized request body: {request.body_size} bytes")
            score = max(score, 0.3)

        # Check for duplicate Content-Type headers
        content_type_count = sum(
            1 for k in request.headers if k.lower() == "content-type"
        )
        if content_type_count > 1:
            evidence.append("Duplicate Content-Type headers")
            score = max(score, 0.5)

        # Check for unusual Content-Length
        content_length_str = request.headers.get("content-length", "0")
        try:
            content_length = int(content_length_str)
            if content_length < 0:
                evidence.append("Negative Content-Length")
                score = max(score, 0.9)
        except ValueError:
            if content_length_str:
                evidence.append(f"Invalid Content-Length: {content_length_str}")
                score = max(score, 0.7)

        # Calculate confidence
        if evidence:
            confidence = min(1.0, 0.5 + len(evidence) * 0.15)
            reason = f"Malformed request detected: {len(evidence)} issue(s) found"
        else:
            confidence = 0.0
            reason = "Request appears well-formed"

        return self._create_result(score, confidence, reason, evidence)
