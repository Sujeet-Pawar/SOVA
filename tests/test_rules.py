"""Tests for Rule-based Detection."""

import pytest
from app.request_processing.parser import HTTPRequest
from app.detection.rules.sqli import SQLiDetector
from app.detection.rules.xss import XSSDetector
from app.detection.rules.traversal import TraversalDetector
from app.detection.rules.command_injection import CommandInjectionDetector
from app.detection.rules.malformed import MalformedRequestDetector
from app.detection.rules.base import RuleEngine
from app.detection.common.models import ThreatType


class TestSQLiDetector:
    """Test SQL Injection detection."""

    def setup_method(self):
        self.detector = SQLiDetector()

    def test_detect_or_injection(self):
        """Test detection of OR-based SQL injection."""
        request = HTTPRequest(
            path="/search",
            query_string="q=' OR '1'='1",
            query={"q": ["' OR '1'='1"]},
        )

        result = self.detector.analyze(request)
        assert result.threat_type == ThreatType.SQL_INJECTION
        assert result.score > 0.5
        assert len(result.evidence) > 0

    def test_detect_union_select(self):
        """Test detection of UNION SELECT injection."""
        request = HTTPRequest(
            path="/search",
            query_string="q=' UNION SELECT NULL,NULL,NULL--",
            query={"q": ["' UNION SELECT NULL,NULL,NULL--"]},
        )

        result = self.detector.analyze(request)
        assert result.threat_type == ThreatType.SQL_INJECTION
        assert result.score > 0.5

    def test_detect_comment_injection(self):
        """Test detection of SQL comment injection."""
        request = HTTPRequest(
            path="/search",
            query_string="q=admin'--",
            query={"q": ["admin'--"]},
        )

        result = self.detector.analyze(request)
        assert result.threat_type == ThreatType.SQL_INJECTION
        assert result.score > 0.3

    def test_no_false_positive_normal(self):
        """Test no false positive on normal request."""
        request = HTTPRequest(
            path="/search",
            query_string="q=laptop",
            query={"q": ["laptop"]},
        )

        result = self.detector.analyze(request)
        assert result.threat_type == ThreatType.NONE
        assert result.score == 0.0


class TestXSSDetector:
    """Test XSS detection."""

    def setup_method(self):
        self.detector = XSSDetector()

    def test_detect_script_tag(self):
        """Test detection of script tag injection."""
        request = HTTPRequest(
            path="/search",
            query_string="q=<script>alert('XSS')</script>",
            query={"q": ["<script>alert('XSS')</script>"]},
        )

        result = self.detector.analyze(request)
        assert result.threat_type == ThreatType.XSS
        assert result.score > 0.5

    def test_detect_img_onerror(self):
        """Test detection of img onerror handler."""
        request = HTTPRequest(
            path="/search",
            query_string="q=<img src=x onerror=alert(1)>",
            query={"q": ["<img src=x onerror=alert(1)>"]},
        )

        result = self.detector.analyze(request)
        assert result.threat_type == ThreatType.XSS
        assert result.score > 0.5

    def test_detect_javascript_protocol(self):
        """Test detection of javascript: protocol."""
        request = HTTPRequest(
            path="/redirect",
            query_string="url=javascript:alert(1)",
            query={"url": ["javascript:alert(1)"]},
        )

        result = self.detector.analyze(request)
        assert result.threat_type == ThreatType.XSS
        assert result.score > 0.3

    def test_no_false_positive_normal(self):
        """Test no false positive on normal request."""
        request = HTTPRequest(
            path="/search",
            query_string="q=hello world",
            query={"q": ["hello world"]},
        )

        result = self.detector.analyze(request)
        assert result.score == 0.0


class TestTraversalDetector:
    """Test Path Traversal detection."""

    def setup_method(self):
        self.detector = TraversalDetector()

    def test_detect_traversal(self):
        """Test detection of path traversal."""
        request = HTTPRequest(
            path="/download",
            query_string="file=../../../etc/passwd",
            query={"file": ["../../../etc/passwd"]},
        )

        result = self.detector.analyze(request)
        assert result.threat_type == ThreatType.PATH_TRAVERSAL
        assert result.score > 0.5

    def test_detect_url_encoded_traversal(self):
        """Test detection of URL-encoded traversal."""
        request = HTTPRequest(
            path="/download",
            query_string="file=..%2f..%2f..%2fetc/passwd",
            query={"file": ["..%2f..%2f..%2fetc/passwd"]},
        )

        result = self.detector.analyze(request)
        assert result.threat_type == ThreatType.PATH_TRAVERSAL
        assert result.score > 0.5

    def test_no_false_positive_normal(self):
        """Test no false positive on normal file path."""
        request = HTTPRequest(
            path="/download",
            query_string="file=report.pdf",
            query={"file": ["report.pdf"]},
        )

        result = self.detector.analyze(request)
        assert result.score == 0.0


class TestCommandInjectionDetector:
    """Test Command Injection detection."""

    def setup_method(self):
        self.detector = CommandInjectionDetector()

    def test_detect_pipe_injection(self):
        """Test detection of pipe-based command injection."""
        request = HTTPRequest(
            path="/search",
            query_string="q=test; ls -la",
            query={"q": ["test; ls -la"]},
        )

        result = self.detector.analyze(request)
        assert result.threat_type == ThreatType.COMMAND_INJECTION
        assert result.score > 0.3

    def test_detect_backtick(self):
        """Test detection of backtick command substitution."""
        request = HTTPRequest(
            path="/search",
            query_string="q=`whoami`",
            query={"q": ["`whoami`"]},
        )

        result = self.detector.analyze(request)
        assert result.threat_type == ThreatType.COMMAND_INJECTION
        assert result.score > 0.3

    def test_no_false_positive_normal(self):
        """Test no false positive on normal request."""
        request = HTTPRequest(
            path="/search",
            query_string="q=hello",
            query={"q": ["hello"]},
        )

        result = self.detector.analyze(request)
        assert result.score == 0.0


class TestMalformedRequestDetector:
    """Test Malformed Request detection."""

    def setup_method(self):
        self.detector = MalformedRequestDetector()

    def test_detect_invalid_method(self):
        """Test detection of invalid HTTP method."""
        request = HTTPRequest(method="INVALID", path="/")

        result = self.detector.analyze(request)
        assert result.threat_type == ThreatType.MALFORMED
        assert result.score > 0.5

    def test_detect_null_byte(self):
        """Test detection of null byte in path."""
        request = HTTPRequest(method="GET", path="/test\x00.html")

        result = self.detector.analyze(request)
        assert result.threat_type == ThreatType.MALFORMED
        assert result.score > 0.5

    def test_no_false_positive_normal(self):
        """Test no false positive on normal request."""
        request = HTTPRequest(
            method="GET",
            path="/search",
            headers={"host": "127.0.0.1"},
        )

        result = self.detector.analyze(request)
        assert result.score == 0.0


class TestRuleEngine:
    """Test the complete rule engine."""

    def setup_method(self):
        self.engine = RuleEngine()

    def test_analyze_normal_request(self):
        """Test analysis of normal request."""
        request = HTTPRequest(
            method="GET",
            path="/search",
            query_string="q=laptop",
            query={"q": ["laptop"]},
            headers={"host": "127.0.0.1"},
        )

        results = self.engine.analyze(request)
        assert len(results) > 0
        # All should be low/no threat for normal request
        for result in results:
            assert result.score == 0.0

    def test_analyze_attack_request(self):
        """Test analysis of attack request."""
        request = HTTPRequest(
            method="GET",
            path="/search",
            query_string="q=' OR 1=1--",
            query={"q": ["' OR 1=1--"]},
        )

        results = self.engine.analyze(request)
        # At least one detector should flag this
        threat_results = [r for r in results if r.threat_type != ThreatType.NONE]
        assert len(threat_results) > 0
        assert any(r.score > 0 for r in threat_results)

    def test_top_threat(self):
        """Test getting the top threat."""
        request = HTTPRequest(
            method="GET",
            path="/search",
            query_string="q=<script>alert(1)</script>",
            query={"q": ["<script>alert(1)</script>"]},
        )

        top = self.engine.analyze_top_threat(request)
        assert top is not None
        assert top.score > 0
