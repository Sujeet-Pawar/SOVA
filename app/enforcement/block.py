"""Block Action and Enforcement Engine.

Decides the final action based on security signals.
"""

from app.detection.common.models import SecuritySignals
from app.enforcement.allow import AllowHandler
from app.enforcement.flag import FlagHandler


class BlockHandler:
    """Handles BLOCK decisions - request is blocked."""

    def __init__(self):
        self.action = "BLOCK"
        self.description = "Request blocked by WAF"

    def execute(self, signals: SecuritySignals) -> dict:
        """Execute the block action."""
        return {
            "action": self.action,
            "description": self.description,
            "known_threat_score": signals.known_threat_score,
            "anomaly_score": signals.anomaly_score,
            "behavior_score": signals.behavior_score,
            "blocked_threats": [
                t.threat_type.value for t in signals.detected_threats
                if t.score > 0
            ],
            "explanations": signals.explanations,
        }


class EnforcementEngine:
    """Decides the final action based on combined security signals.

    Policy:
        - High rule score → BLOCK (known attack)
        - High anomaly + no strong rule match → FLAG (unknown behavior)
        - Low scores → ALLOW
    """

    def __init__(self, config: dict = None):
        config = config or {}
        self.block_threshold = config.get("block_threshold", 0.8)
        self.flag_threshold = config.get("flag_threshold", 0.5)
        self.allow_threshold = config.get("allow_threshold", 0.3)

        self.allow_handler = AllowHandler()
        self.flag_handler = FlagHandler()
        self.block_handler = BlockHandler()

    def decide(self, signals: SecuritySignals) -> str:
        """Make the final enforcement decision.

        Returns:
            "ALLOW", "FLAG", or "BLOCK"
        """
        # Rule 1: Known high-confidence threat → BLOCK
        if signals.known_threat_score >= self.block_threshold:
            return "BLOCK"

        # Rule 2: Multiple high scores → BLOCK
        high_scores = sum(1 for s in [
            signals.known_threat_score,
            signals.anomaly_score,
            signals.behavior_score,
        ] if s >= self.flag_threshold)

        if high_scores >= 2:
            return "BLOCK"

        # Rule 3: Known threat above flag threshold → FLAG
        if signals.known_threat_score >= self.flag_threshold:
            return "FLAG"

        # Rule 4: High anomaly with suspicious behavior → FLAG or BLOCK
        if signals.anomaly_score >= self.flag_threshold:
            if signals.behavior_score >= self.flag_threshold:
                return "BLOCK"
            return "FLAG"

        # Rule 5: High behavior score with some rule match → FLAG
        if signals.behavior_score >= self.flag_threshold:
            if signals.known_threat_score >= 0.3:
                return "FLAG"

        # Rule 6: Moderate anomaly → FLAG
        if signals.anomaly_score >= self.allow_threshold:
            return "FLAG"

        # Default: ALLOW
        return "ALLOW"

    def execute(self, signals: SecuritySignals) -> dict:
        """Make and execute the enforcement decision."""
        action = self.decide(signals)

        if action == "BLOCK":
            return self.block_handler.execute(signals)
        elif action == "FLAG":
            return self.flag_handler.execute(signals)
        else:
            return self.allow_handler.execute(signals)
