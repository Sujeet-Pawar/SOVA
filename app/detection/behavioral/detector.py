"""Behavioral Detector - detects suspicious behavior patterns."""

from app.request_processing.parser import HTTPRequest
from app.detection.behavioral.session_tracker import SessionTracker
from app.detection.common.models import BehavioralResult


class BehavioralDetector:
    """Detects suspicious behavior based on session patterns."""

    def __init__(self, config: dict = None):
        config = config or {}
        self.tracker = SessionTracker(session_ttl=config.get("session_ttl", 300))
        self.high_frequency_threshold = config.get("high_frequency_threshold", 20)
        self.low_diversity_threshold = config.get("low_diversity_threshold", 0.2)
        self.high_failure_rate = config.get("high_failure_rate", 0.5)

    def detect(self, request: HTTPRequest) -> BehavioralResult:
        """Analyze request behavior and return a behavioral score."""
        session_id = request.session_id

        # Record the request
        self.tracker.record_request(request)

        # Get session stats
        stats = self.tracker.get_session_stats(session_id)

        # Calculate behavioral score
        behavior_score = 0.0
        reasons = []

        # High request frequency
        if stats["request_count_60s"] > self.high_frequency_threshold:
            behavior_score += 0.3
            reasons.append(
                f"High request frequency: {stats['request_count_60s']} requests in 60s"
            )

        # Low endpoint diversity (repeated hitting same endpoint)
        if (stats["total_requests"] > 5 and
                stats["endpoint_diversity"] < self.low_diversity_threshold):
            behavior_score += 0.2
            reasons.append(
                f"Low endpoint diversity: {stats['endpoint_diversity']:.2f} "
                f"({stats['unique_endpoints']} unique / {stats['total_requests']} total)"
            )

        # High failure rate
        if stats["failure_rate"] > self.high_failure_rate and stats["total_requests"] > 3:
            behavior_score += 0.25
            reasons.append(
                f"High failure rate: {stats['failure_rate']:.1%} "
                f"({stats['failed_count']} failures / {stats['total_requests']} total)"
            )

        # Rapid sequential requests (more than 5 in 10 seconds)
        if stats["request_count_10s"] > 5:
            behavior_score += 0.15
            reasons.append(
                f"Rapid requests: {stats['request_count_10s']} in 10s"
            )

        # Multiple IPs for same session (session hijacking indicator)
        if stats["unique_ips"] > 3:
            behavior_score += 0.1
            reasons.append(
                f"Multiple IPs in session: {stats['unique_ips']}"
            )

        behavior_score = min(1.0, behavior_score)

        # Classify
        if behavior_score >= 0.5:
            classification = "SUSPICIOUS"
            reason_text = "Suspicious behavior detected: " + "; ".join(reasons)
        else:
            classification = "NORMAL"
            reason_text = "Behavior within normal parameters"

        return BehavioralResult(
            behavior_score=behavior_score,
            classification=classification,
            reason=reason_text,
            details=stats,
        )
