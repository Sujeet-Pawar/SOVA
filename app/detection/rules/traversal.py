"""Path Traversal Detector - detects directory traversal attempts."""

import re
from app.request_processing.parser import HTTPRequest
from app.detection.common.models import DetectionResult, ThreatType
from app.detection.rules.base import BaseDetector


class TraversalDetector(BaseDetector):
    """Detects path traversal attempts."""

    name = "TraversalRuleDetector"
    threat_type = ThreatType.PATH_TRAVERSAL

    PATTERNS = {
        # High severity
        "high": [
            (r"\.\./\.\./\.\.", "Deep directory traversal"),
            (r"\.\.\\", "Windows-style traversal"),
            (r"%2e%2e%2f", "URL-encoded traversal"),
            (r"%2e%2e/", "Partial URL-encoded traversal"),
            (r"\.\.%2f", "Mixed traversal encoding"),
            (r"%2e%2e%5c", "URL-encoded backslash traversal"),
        ],
        # Medium severity
        "medium": [
            (r"\.\./", "Standard traversal"),
            (r"\.\.%2f", "Partial URL-encoded"),
            (r"%2e%2e", "Double URL-encoded dots"),
            (r"(\.\./){2,}", "Multiple traversals"),
        ],
        # Low severity
        "low": [
            (r"\.\./\w+", "Traversal to directory"),
            (r"(\.\./)", "Single traversal indicator"),
        ],
    }

    # Sensitive files often targeted
    SENSITIVE_PATHS = [
        r"/etc/passwd",
        r"/etc/shadow",
        r"/etc/hosts",
        r"win\.ini",
        r"boot\.ini",
        r"/proc/self",
        r"\\.env",
        r"password",
        r"shadow",
        r"htpasswd",
    ]

    def analyze(self, request: HTTPRequest) -> DetectionResult:
        """Analyze request for path traversal patterns."""
        text = self._get_analyzable_text(request)
        evidence = []
        max_score = 0.0

        # Check high severity patterns
        for pattern, description in self.PATTERNS["high"]:
            if re.search(pattern, text, re.IGNORECASE):
                evidence.append(f"HIGH: {description}")
                max_score = max(max_score, 0.95)

        # Check medium severity patterns
        for pattern, description in self.PATTERNS["medium"]:
            if re.search(pattern, text, re.IGNORECASE):
                evidence.append(f"MED: {description}")
                max_score = max(max_score, 0.7)

        # Check low severity patterns
        for pattern, description in self.PATTERNS["low"]:
            if re.search(pattern, text, re.IGNORECASE):
                evidence.append(f"LOW: {description}")
                max_score = max(max_score, 0.4)

        # Check for sensitive file paths
        for pattern in self.SENSITIVE_PATHS:
            if re.search(pattern, text, re.IGNORECASE):
                evidence.append(f"SENSITIVE: Targeting sensitive path: {pattern}")
                max_score = max(max_score, 0.8)

        # Calculate final score
        if evidence:
            score = min(1.0, max_score + min(0.1, len(evidence) * 0.03))
            confidence = min(1.0, 0.5 + len(evidence) * 0.15)
            reason = f"Path traversal indicators detected: {len(evidence)} pattern(s) matched"
        else:
            score = 0.0
            confidence = 0.0
            reason = "No path traversal patterns detected"

        return self._create_result(score, confidence, reason, evidence)
