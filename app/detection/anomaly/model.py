"""Anomaly Detection Model - wrapper around Isolation Forest."""

import numpy as np
from typing import Optional
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
from pathlib import Path


class AnomalyModel:
    """Wraps the Isolation Forest anomaly detection model."""

    def __init__(self, contamination: float = 0.1, n_estimators: int = 100, random_state: int = 42):
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state

        self.model: Optional[IsolationForest] = None
        self.scaler: Optional[StandardScaler] = None
        self.is_trained = False

    def train(self, X: np.ndarray):
        """Train the Isolation Forest model on normal traffic features."""
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        self.model = IsolationForest(
            contamination=self.contamination,
            n_estimators=self.n_estimators,
            random_state=self.random_state,
            warm_start=False,
        )
        self.model.fit(X_scaled)
        self.is_trained = True

        # Store reference scores from training data for normalization
        train_scores = self.model.score_samples(X_scaled)
        self._score_min = float(np.min(train_scores))
        self._score_max = float(np.max(train_scores))

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict anomaly labels. Returns -1 for anomalies, 1 for normal."""
        if not self.is_trained:
            raise RuntimeError("Model not trained. Call train() first.")
        X_scaled = self.scaler.transform(X)
        return self.model.predict(X_scaled)

    def score(self, X: np.ndarray) -> np.ndarray:
        """Get anomaly scores. Returns values in [0, 1] where 1 is most anomalous."""
        if not self.is_trained:
            raise RuntimeError("Model not trained. Call train() first.")
        X_scaled = self.scaler.transform(X)
        raw_scores = self.model.score_samples(X_scaled)
        # Normalize using training data reference range
        # Lower raw scores = more anomalous, so invert
        score_range = self._score_max - self._score_min
        if score_range > 0:
            normalized = (self._score_max - raw_scores) / score_range
        else:
            normalized = np.zeros_like(raw_scores)
        # Clamp to [0, 1]
        return np.clip(normalized, 0.0, 1.0)

    def save(self, path: str):
        """Save the model to disk."""
        if not self.is_trained:
            raise RuntimeError("No trained model to save.")
        joblib.dump({
            "model": self.model,
            "scaler": self.scaler,
            "contamination": self.contamination,
            "score_min": self._score_min,
            "score_max": self._score_max,
        }, path)

    def load(self, path: str):
        """Load the model from disk."""
        data = joblib.load(path)
        self.model = data["model"]
        self.scaler = data["scaler"]
        self.contamination = data.get("contamination", self.contamination)
        self._score_min = data.get("score_min", -1.0)
        self._score_max = data.get("score_max", 0.0)
        self.is_trained = True
