"""Base Rule Engine and Detector Interface.

All detectors implement the same interface:
    analyze(request) -> DetectionResult
"""

import re
from abc import ABC, abstractmethod
from typing import Optional
from app.request_processing.parser import HTTPRequest
from app.detection.common.models import DetectionResult, ThreatType


class BaseDetector(ABC):
    """Abstract base class for all rule-based detectors."""

    name: str = "BaseDetector"
    threat_type: ThreatType = ThreatType.NONE

    @abstractmethod
    def analyze(self, request: HTTPRequest) -> DetectionResult:
        """Analyze a request and return a detection result."""
        pass

    def _create_result(
        self,
        score: float,
        confidence: float,
        reason: str,
        evidence: Optional[list[str]] = None,
    ) -> DetectionResult:
        """Create a standardized DetectionResult."""
        # Only report threat type if there's actual evidence
        threat_type = self.threat_type if score > 0 else ThreatType.NONE
        return DetectionResult(
            detector=self.name,
            threat_type=threat_type,
            score=score,
            confidence=confidence,
            reason=reason,
            evidence=evidence or [],
        )

    def _get_analyzable_text(self, request: HTTPRequest) -> str:
        """Get combined text for analysis from request."""
        parts = [
            request.path,
            request.query_string,
        ]
        # Add body fields (not raw body, just field names for context)
        parts.extend(request.body_fields)
        return " ".join(parts)


class RuleEngine:
    """Rule engine that runs all detectors and aggregates results."""

    def __init__(self):
        self.detectors: list[BaseDetector] = []
        self._register_detectors()

    def _register_detectors(self):
        """Register all available detectors."""
        from app.detection.rules.sqli import SQLiDetector
        from app.detection.rules.xss import XSSDetector
        from app.detection.rules.traversal import TraversalDetector
        from app.detection.rules.command_injection import CommandInjectionDetector
        from app.detection.rules.malformed import MalformedRequestDetector

        self.detectors = [
            SQLiDetector(),
            XSSDetector(),
            TraversalDetector(),
            CommandInjectionDetector(),
            MalformedRequestDetector(),
        ]

    def analyze(self, request: HTTPRequest) -> list[DetectionResult]:
        """Run all detectors and return results."""
        results = []
        for detector in self.detectors:
            try:
                result = detector.analyze(request)
                results.append(result)
            except Exception as e:
                # Detector failed, record error
                results.append(DetectionResult(
                    detector=detector.name,
                    threat_type=ThreatType.NONE,
                    score=0.0,
                    confidence=0.0,
                    reason=f"Detector error: {str(e)}",
                ))
        return results

    def analyze_top_threat(self, request: HTTPRequest) -> Optional[DetectionResult]:
        """Return only the highest-scoring threat detection."""
        results = self.analyze(request)
        threat_results = [r for r in results if r.threat_type != ThreatType.NONE and r.score > 0]
        if threat_results:
            return max(threat_results, key=lambda r: r.score)
        return None
