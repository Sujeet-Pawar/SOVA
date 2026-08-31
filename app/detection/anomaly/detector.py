"""Anomaly Detector - real-time anomaly detection for incoming requests."""

import os
import numpy as np
from pathlib import Path
from typing import Optional
from app.feature_engine.pipeline import FeatureVector
from app.detection.anomaly.model import AnomalyModel
from app.detection.common.models import AnomalyResult


class AnomalyDetector:
    """Detects anomalies in incoming requests using the trained Isolation Forest."""

    def __init__(self, model_path: Optional[str] = None, threshold: float = 0.6):
        self.threshold = threshold
        self.model = AnomalyModel()

        # Try to load existing model
        if model_path and os.path.exists(model_path):
            self.model.load(model_path)
        else:
            # Try default path
            default_path = Path(__file__).parent.parent.parent.parent / "data" / "models" / "anomaly_model.joblib"
            if default_path.exists():
                self.model.load(str(default_path))

    def detect(self, feature_vector: FeatureVector) -> Optional[AnomalyResult]:
        """Detect if a request is anomalous."""
        if not self.model.is_trained:
            # No model trained yet - return neutral result
            return AnomalyResult(
                anomaly_score=0.0,
                classification="UNKNOWN",
                reason="No anomaly model loaded",
            )

        try:
            # Get anomaly score
            X = feature_vector.to_numpy().reshape(1, -1)
            scores = self.model.score(X)
            anomaly_score = float(scores[0])

            # Classify
            if anomaly_score >= self.threshold:
                classification = "ANOMALOUS"
                reason = f"Request deviates significantly from normal traffic (score: {anomaly_score:.3f})"
            else:
                classification = "NORMAL"
                reason = f"Request is within normal parameters (score: {anomaly_score:.3f})"

            return AnomalyResult(
                anomaly_score=anomaly_score,
                classification=classification,
                reason=reason,
            )

        except Exception as e:
            return AnomalyResult(
                anomaly_score=0.0,
                classification="ERROR",
                reason=f"Anomaly detection error: {str(e)}",
            )
