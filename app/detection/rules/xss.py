"""XSS Detector - detects Cross-Site Scripting patterns."""

import re
from app.request_processing.parser import HTTPRequest
from app.detection.common.models import DetectionResult, ThreatType
from app.detection.rules.base import BaseDetector


class XSSDetector(BaseDetector):
    """Detects XSS attempts using pattern matching."""

    name = "XSSRuleDetector"
    threat_type = ThreatType.XSS

    PATTERNS = {
        # High severity
        "high": [
            (r"<script[^>]*>.*</script>", "Script tag injection"),
            (r"javascript\s*:", "JavaScript protocol"),
            (r"on\w+\s*=\s*['\"]?\s*\w+", "Inline event handler"),
            (r"<\s*iframe[^>]*>", "iFrame injection"),
            (r"<\s*object[^>]*>", "Object tag injection"),
            (r"<\s*embed[^>]*>", "Embed tag injection"),
            (r"<\s*applet[^>]*>", "Applet tag injection"),
        ],
        # Medium severity
        "medium": [
            (r"<\s*img[^>]*\bonerror\b", "Image onerror handler"),
            (r"<\s*svg[^>]*\bonload\b", "SVG onload handler"),
            (r"<\s*body[^>]*\bonload\b", "Body onload handler"),
            (r"eval\s*\(", "eval() function"),
            (r"document\.(cookie|write|location)", "DOM manipulation"),
            (r"window\.(location|open|eval)", "Window manipulation"),
            (r"<\s*(div|span|p|a|input|form|table)[^>]*style\s*=\s*['\"]?.*expression", "CSS expression"),
        ],
        # Low severity
        "low": [
            (r"<\s*script", "Script tag"),
            (r"<\s*img[^>]*>", "Image tag"),
            (r"<\s*svg[^>]*>", "SVG tag"),
            (r"<\s*style[^>]*>", "Style tag"),
            (r"(alert|confirm|prompt)\s*\(", "Dialog function"),
        ],
    }

    # Encoding patterns that may indicate XSS obfuscation
    ENCODING_PATTERNS = [
        (r"&#\d+;", "HTML decimal entity"),
        (r"&#x[0-9a-fA-F]+;", "HTML hex entity"),
        (r"\\x[0-9a-fA-F]{2}", "Hex escape"),
        (r"\\u[0-9a-fA-F]{4}", "Unicode escape"),
        (r"%[0-9a-fA-F]{2}", "URL encoding"),
    ]

    def analyze(self, request: HTTPRequest) -> DetectionResult:
        """Analyze request for XSS patterns."""
        text = self._get_analyzable_text(request)
        evidence = []
        max_score = 0.0

        # Check high severity
        for pattern, description in self.PATTERNS["high"]:
            if re.search(pattern, text, re.IGNORECASE):
                evidence.append(f"HIGH: {description}")
                max_score = max(max_score, 0.9)

        # Check medium severity
        for pattern, description in self.PATTERNS["medium"]:
            if re.search(pattern, text, re.IGNORECASE):
                evidence.append(f"MED: {description}")
                max_score = max(max_score, 0.7)

        # Check low severity
        for pattern, description in self.PATTERNS["low"]:
            if re.search(pattern, text, re.IGNORECASE):
                evidence.append(f"LOW: {description}")
                max_score = max(max_score, 0.4)

        # Check for encoding obfuscation
        encoding_count = 0
        for pattern, description in self.ENCODING_PATTERNS:
            matches = re.findall(pattern, text)
            if matches:
                encoding_count += len(matches)
                evidence.append(f"ENC: {description} ({len(matches)} instances)")

        if encoding_count > 3:
            max_score = max(max_score, 0.6)

        # Calculate final score
        if evidence:
            score = min(1.0, max_score + min(0.2, len(evidence) * 0.05))
            confidence = min(1.0, 0.5 + len(evidence) * 0.15)
            reason = f"XSS indicators detected: {len(evidence)} pattern(s) matched"
        else:
            score = 0.0
            confidence = 0.0
            reason = "No XSS patterns detected"

        return self._create_result(score, confidence, reason, evidence)
