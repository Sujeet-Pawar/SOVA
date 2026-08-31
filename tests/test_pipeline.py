"""Integration Tests for the Full Detection Pipeline."""

import pytest
from app.request_processing.parser import HTTPRequest
from app.feature_engine.pipeline import FeaturePipeline
from app.detection.rules.base import RuleEngine
from app.detection.common.models import SecuritySignals, ThreatType
from app.enforcement.block import EnforcementEngine


class TestFullPipeline:
    """Test the complete detection pipeline integration."""

    def setup_method(self):
        self.pipeline = FeaturePipeline()
        self.rule_engine = RuleEngine()
        self.enforcement = EnforcementEngine({
            "block_threshold": 0.8,
            "flag_threshold": 0.5,
            "allow_threshold": 0.3,
        })

    def test_normal_request_allow(self):
        """Test that normal requests are allowed."""
        request = HTTPRequest(
            method="GET",
            path="/",
            query_string="",
            query={},
            headers={"host": "127.0.0.1", "user-agent": "Mozilla/5.0"},
            session_id="NORMAL_SESSION",
            source_id="CLIENT-001",
        )
        request.compute_lengths()

        # Feature extraction
        fv = self.pipeline.extract(request)
        assert fv.values.shape[0] > 0

        # Rule detection
        rule_results = self.rule_engine.analyze(request)
        max_rule_score = max((r.score for r in rule_results), default=0)

        # Build signals
        signals = SecuritySignals(
            known_threat_score=max_rule_score,
            anomaly_score=0.0,
            behavior_score=0.0,
            detected_threats=[r for r in rule_results if r.score > 0],
        )

        # Decision
        action = self.enforcement.decide(signals)
        assert action == "ALLOW"

    def test_sqli_request_block(self):
        """Test that SQL injection requests are blocked."""
        # Use a high-severity payload (UNION SELECT) that scores above 0.8
        request = HTTPRequest(
            method="GET",
            path="/search",
            query_string="q=' UNION SELECT NULL,NULL,NULL--",
            query={"q": ["' UNION SELECT NULL,NULL,NULL--"]},
            headers={"host": "127.0.0.1"},
            session_id="ATTACK_SESSION",
            source_id="ATTACKER",
        )
        request.compute_lengths()

        # Feature extraction
        fv = self.pipeline.extract(request)

        # Rule detection
        rule_results = self.rule_engine.analyze(request)
        max_rule_score = max((r.score for r in rule_results), default=0)

        # Build signals
        signals = SecuritySignals(
            known_threat_score=max_rule_score,
            anomaly_score=0.0,
            behavior_score=0.0,
            detected_threats=[r for r in rule_results if r.score > 0],
        )

        # Decision
        action = self.enforcement.decide(signals)
        assert action == "BLOCK"

    def test_sqli_request_flag(self):
        """Test that moderate SQL injection is flagged."""
        request = HTTPRequest(
            method="GET",
            path="/search",
            query_string="q=' OR '1'='1",
            query={"q": ["' OR '1'='1"]},
            headers={"host": "127.0.0.1"},
            session_id="ATTACK_SESSION",
            source_id="ATTACKER",
        )
        request.compute_lengths()

        rule_results = self.rule_engine.analyze(request)
        max_rule_score = max((r.score for r in rule_results), default=0)

        signals = SecuritySignals(
            known_threat_score=max_rule_score,
            anomaly_score=0.0,
            behavior_score=0.0,
            detected_threats=[r for r in rule_results if r.score > 0],
        )

        action = self.enforcement.decide(signals)
        # Moderate SQLi should be flagged or blocked
        assert action in ("FLAG", "BLOCK")

    def test_xss_request_block(self):
        """Test that XSS requests are blocked."""
        request = HTTPRequest(
            method="GET",
            path="/search",
            query_string="q=<script>alert('XSS')</script>",
            query={"q": ["<script>alert('XSS')</script>"]},
            headers={"host": "127.0.0.1"},
            session_id="ATTACK_SESSION",
            source_id="ATTACKER",
        )
        request.compute_lengths()

        # Rule detection
        rule_results = self.rule_engine.analyze(request)
        max_rule_score = max((r.score for r in rule_results), default=0)

        signals = SecuritySignals(
            known_threat_score=max_rule_score,
            anomaly_score=0.0,
            behavior_score=0.0,
            detected_threats=[r for r in rule_results if r.score > 0],
        )

        action = self.enforcement.decide(signals)
        assert action == "BLOCK"

    def test_traversal_request_block(self):
        """Test that path traversal requests are blocked."""
        request = HTTPRequest(
            method="GET",
            path="/download",
            query_string="file=../../../etc/passwd",
            query={"file": ["../../../etc/passwd"]},
            headers={"host": "127.0.0.1"},
            session_id="ATTACK_SESSION",
            source_id="ATTACKER",
        )
        request.compute_lengths()

        rule_results = self.rule_engine.analyze(request)
        max_rule_score = max((r.score for r in rule_results), default=0)

        signals = SecuritySignals(
            known_threat_score=max_rule_score,
            anomaly_score=0.0,
            behavior_score=0.0,
            detected_threats=[r for r in rule_results if r.score > 0],
        )

        action = self.enforcement.decide(signals)
        assert action == "BLOCK"

    def test_anomalous_request_flag(self):
        """Test that anomalous requests are flagged."""
        signals = SecuritySignals(
            known_threat_score=0.1,
            anomaly_score=0.7,
            behavior_score=0.0,
        )

        action = self.enforcement.decide(signals)
        assert action == "FLAG"

    def test_combined_high_threat_block(self):
        """Test that combined high signals result in block."""
        signals = SecuritySignals(
            known_threat_score=0.6,
            anomaly_score=0.6,
            behavior_score=0.0,
        )

        action = self.enforcement.decide(signals)
        assert action == "BLOCK"

    def test_all_scores_low_allow(self):
        """Test that low scores result in allow."""
        signals = SecuritySignals(
            known_threat_score=0.05,
            anomaly_score=0.1,
            behavior_score=0.1,
        )

        action = self.enforcement.decide(signals)
        assert action == "ALLOW"


class TestSecuritySignals:
    """Test security signals model."""

    def test_default_signals(self):
        """Test default signal values."""
        signals = SecuritySignals()
        assert signals.known_threat_score == 0.0
        assert signals.anomaly_score == 0.0
        assert signals.behavior_score == 0.0
        assert signals.action == "ALLOW"
        assert len(signals.explanations) == 0

    def test_signals_with_threats(self):
        """Test signals with detected threats."""
        from app.detection.common.models import DetectionResult

        threat = DetectionResult(
            detector="SQLiDetector",
            threat_type=ThreatType.SQL_INJECTION,
            score=0.9,
            confidence=0.95,
            reason="SQL injection detected",
        )

        signals = SecuritySignals(
            known_threat_score=0.9,
            detected_threats=[threat],
            explanations=["SQL injection detected"],
        )

        assert signals.known_threat_score == 0.9
        assert len(signals.detected_threats) == 1
        assert signals.detected_threats[0].threat_type == ThreatType.SQL_INJECTION
