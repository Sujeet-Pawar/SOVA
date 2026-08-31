"""SQL Injection Detector - detects SQL injection patterns."""

import re
from app.request_processing.parser import HTTPRequest
from app.detection.common.models import DetectionResult, ThreatType
from app.detection.rules.base import BaseDetector


class SQLiDetector(BaseDetector):
    """Detects SQL injection attempts using pattern matching."""

    name = "SQLiRuleDetector"
    threat_type = ThreatType.SQL_INJECTION

    # SQL injection patterns organized by severity
    PATTERNS = {
        # High severity - almost certainly malicious
        "high": [
            (re.compile(r"(?i)\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|EXEC|EXECUTE)\b.*\b(FROM|INTO|WHERE|SET|TABLE|DATABASE|EXEC|EXECUTE)\b"), "SQL keyword combination"),
            (re.compile(r"(?i)\bOR\b\s+\d+\s*=\s*\d+"), "Always-true numeric condition"),
            (re.compile(r"(?i)\bAND\b\s+\d+\s*=\s*\d+"), "Always-true numeric condition with AND"),
            (re.compile(r"(?i)--\s*$|/\*.*?\*/"), "SQL comment injection"),
            (re.compile(r"(?i)\bWAITFOR\b\s+\bDELAY\b"), "Time-based blind SQLi"),
            (re.compile(r"(?i)\bSLEEP\s*\("), "Sleep-based blind SQLi"),
            (re.compile(r"(?i)\bBENCHMARK\s*\("), "Benchmark-based blind SQLi"),
        ],
        # Medium severity - suspicious
        "medium": [
            (re.compile(r"(?i)\bUNION\b\s+\bSELECT\b"), "UNION SELECT injection"),
            (re.compile(r"(?i)\bSELECT\b\s+\*"), "Wildcard SELECT"),
            (re.compile(r"(?i)\bDROP\b\s+\bTABLE\b"), "DROP TABLE attempt"),
            (re.compile(r"(?i)\bINSERT\b\s+\bINTO\b"), "INSERT INTO attempt"),
            (re.compile(r"(?i)\bDELETE\b\s+\bFROM\b"), "DELETE FROM attempt"),
            (re.compile(r"(?i)\bUPDATE\b\s+\w+\s+\bSET\b"), "UPDATE SET attempt"),
            (re.compile(r"(?i)\bOR\b\s+['\"]"), "OR with quoted value"),
            (re.compile(r"(?i)\bAND\b\s+['\"]"), "AND with quoted value"),
            (re.compile(r"(?i)\bWHERE\b\s+\d+\s*=\s*\d+"), "WHERE with numeric comparison"),
        ],
        # Low severity - indicators
        "low": [
            (re.compile(r"(?i)\bEXEC\b|\bEXECUTE\b"), "EXEC/EXECUTE keyword"),
            (re.compile(r";\s*--"), "Semicolon with comment"),
        ],
    }

    # SQL function/function-like patterns
    SQL_FUNCTIONS = [
        re.compile(r"(?i)\b(CONCAT|CHAR|SUBSTRING|CONVERT|CAST|COALESCE|IFNULL)\s*\("),
        re.compile(r"(?i)\b(ASCII|ORD|HEX|UNHEX|MD5|SHA1|SHA2)\s*\("),
        re.compile(r"(?i)\b(INFORMATION_SCHEMA|SYSOBJECTS|SYSCOLUMNS)\b"),
    ]

    def analyze(self, request: HTTPRequest) -> DetectionResult:
        """Analyze request for SQL injection patterns."""
        text = self._get_analyzable_text(request)
        evidence = []
        max_score = 0.0
        total_weight = 0.0

        # Check high severity patterns
        for pattern, description in self.PATTERNS["high"]:
            if pattern.search(text):
                evidence.append(f"HIGH: {description}")
                max_score = max(max_score, 0.9)
                total_weight += 0.9

        # Check medium severity patterns
        for pattern, description in self.PATTERNS["medium"]:
            if pattern.search(text):
                evidence.append(f"MED: {description}")
                max_score = max(max_score, 0.65)
                total_weight += 0.6

        # Check low severity patterns
        for pattern, description in self.PATTERNS["low"]:
            if pattern.search(text):
                evidence.append(f"LOW: {description}")
                max_score = max(max_score, 0.4)
                total_weight += 0.3

        # Check SQL functions
        for pattern in self.SQL_FUNCTIONS:
            if pattern.search(text):
                evidence.append("FUNC: SQL function detected")
                max_score = max(max_score, 0.6)
                total_weight += 0.4

        # Combine scores
        if evidence:
            # Score increases with more evidence
            score = min(1.0, max_score + min(0.2, total_weight * 0.05))
            confidence = min(1.0, 0.5 + len(evidence) * 0.15)
            reason = f"SQL injection indicators detected: {len(evidence)} pattern(s) matched"
        else:
            score = 0.0
            confidence = 0.0
            reason = "No SQL injection patterns detected"

        return self._create_result(score, confidence, reason, evidence)
