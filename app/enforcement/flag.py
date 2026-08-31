"""Flag Action - marks request for review but allows it through."""

from app.detection.common.models import SecuritySignals


class FlagHandler:
    """Handles FLAG decisions - request is allowed but flagged for review."""

    def __init__(self):
        self.action = "FLAG"
        self.description = "Request flagged for review"

    def execute(self, signals: SecuritySignals) -> dict:
        """Execute the flag action."""
        return {
            "action": self.action,
            "description": self.description,
            "known_threat_score": signals.known_threat_score,
            "anomaly_score": signals.anomaly_score,
            "behavior_score": signals.behavior_score,
            "flagged_threats": [
                t.threat_type.value for t in signals.detected_threats
                if t.score > 0
            ],
            "explanations": signals.explanations,
        }
