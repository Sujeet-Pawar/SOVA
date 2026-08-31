"""Allow Action - permits the request to pass through."""

from app.detection.common.models import SecuritySignals


class AllowHandler:
    """Handles ALLOW decisions - request passes through unchanged."""

    def __init__(self):
        self.action = "ALLOW"
        self.description = "Request permitted through WAF"

    def execute(self, signals: SecuritySignals) -> dict:
        """Execute the allow action."""
        return {
            "action": self.action,
            "description": self.description,
            "known_threat_score": signals.known_threat_score,
            "anomaly_score": signals.anomaly_score,
            "behavior_score": signals.behavior_score,
        }
