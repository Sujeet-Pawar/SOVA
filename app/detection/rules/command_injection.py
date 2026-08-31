"""Command Injection Detector - detects OS command injection attempts."""

import re
from app.request_processing.parser import HTTPRequest
from app.detection.common.models import DetectionResult, ThreatType
from app.detection.rules.base import BaseDetector


class CommandInjectionDetector(BaseDetector):
    """Detects command injection attempts."""

    name = "CommandInjectionRuleDetector"
    threat_type = ThreatType.COMMAND_INJECTION

    PATTERNS = {
        # High severity - almost certainly malicious
        "high": [
            (r"[|;&`]", "Shell metacharacter"),
            (r"\$\(", "Command substitution"),
            (r"`[^`]+`", "Backtick command substitution"),
            (r"\$[A-Za-z_][A-Za-z0-9_]*", "Shell variable expansion"),
            (r">\s*/", "File write redirect"),
            (r"<\s*/", "File read redirect"),
        ],
        # Medium severity
        "medium": [
            (r"(?i)\b(wget|curl|nc|netcat|bash|sh|cmd|powershell)\b", "Command tool name"),
            (r"(?i)\b(chmod|chown|chgrp|rm|mkdir|rmdir)\b", "File system command"),
            (r"(?i)\b(cat|type|more|less|head|tail)\s+/", "File read command"),
            (r"(?i)(;|\|)\s*\w+", "Piped command"),
            (r"(?i)&&\s*\w+", "Chained command"),
        ],
        # Low severity
        "low": [
            (r"(?i)\b(ping|nslookup|dig|host)\b", "Network command"),
            (r"(?i)\b(echo|print)\b", "Output command"),
            (r"(?i)\b(env|set|export|printenv)\b", "Environment command"),
        ],
    }

    # dangerous binary patterns
    DANGEROUS_BINARIES = [
        r"(?i)\b(nc|ncat|netcat)\s+-",
        r"(?i)\b(wget|curl)\s+.*\|\s*(bash|sh)",
        r"(?i)\b(perl|python|ruby|php)\s+-",
    ]

    def analyze(self, request: HTTPRequest) -> DetectionResult:
        """Analyze request for command injection patterns."""
        text = self._get_analyzable_text(request)
        evidence = []
        max_score = 0.0

        # Check high severity
        for pattern, description in self.PATTERNS["high"]:
            if re.search(pattern, text):
                evidence.append(f"HIGH: {description}")
                max_score = max(max_score, 0.9)

        # Check medium severity
        for pattern, description in self.PATTERNS["medium"]:
            if re.search(pattern, text):
                evidence.append(f"MED: {description}")
                max_score = max(max_score, 0.7)

        # Check low severity
        for pattern, description in self.PATTERNS["low"]:
            if re.search(pattern, text):
                evidence.append(f"LOW: {description}")
                max_score = max(max_score, 0.4)

        # Check dangerous binaries
        for pattern in self.DANGEROUS_BINARIES:
            if re.search(pattern, text):
                evidence.append("DANGEROUS: Dangerous binary invocation")
                max_score = max(max_score, 0.85)

        # Calculate final score
        if evidence:
            score = min(1.0, max_score + min(0.15, len(evidence) * 0.05))
            confidence = min(1.0, 0.5 + len(evidence) * 0.12)
            reason = f"Command injection indicators detected: {len(evidence)} pattern(s) matched"
        else:
            score = 0.0
            confidence = 0.0
            reason = "No command injection patterns detected"

        return self._create_result(score, confidence, reason, evidence)
