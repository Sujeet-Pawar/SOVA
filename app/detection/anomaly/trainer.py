"""Anomaly Model Trainer - trains the Isolation Forest on normal traffic."""

import json
import numpy as np
from pathlib import Path
from typing import Optional
from app.feature_engine.pipeline import FeaturePipeline
from app.detection.anomaly.model import AnomalyModel
from app.request_processing.parser import HTTPRequest


class AnomalyTrainer:
    """Trains the anomaly detection model on normal traffic data."""

    def __init__(self, config: Optional[dict] = None):
        config = config or {}
        self.contamination = config.get("contamination", 0.1)
        self.n_estimators = config.get("n_estimators", 100)
        self.random_state = config.get("random_state", 42)

        self.feature_pipeline = FeaturePipeline()
        self.model = AnomalyModel(
            contamination=self.contamination,
            n_estimators=self.n_estimators,
            random_state=self.random_state,
        )

    def train_from_features(self, feature_matrix: np.ndarray) -> dict:
        """Train the model from a pre-computed feature matrix."""
        print(f"Training Isolation Forest on {feature_matrix.shape[0]} samples, "
              f"{feature_matrix.shape[1]} features")

        self.model.train(feature_matrix)

        # Evaluate on training data
        scores = self.model.score(feature_matrix)
        predictions = self.model.predict(feature_matrix)

        stats = {
            "n_samples": feature_matrix.shape[0],
            "n_features": feature_matrix.shape[1],
            "mean_anomaly_score": float(np.mean(scores)),
            "max_anomaly_score": float(np.max(scores)),
            "n_anomalies_detected": int(np.sum(predictions == -1)),
            "anomaly_ratio": float(np.mean(predictions == -1)),
        }

        print(f"Training complete. Anomaly ratio: {stats['anomaly_ratio']:.2%}")
        return stats

    def train_from_jsonl(self, jsonl_path: str) -> dict:
        """Train from a JSONL file of normalized requests."""
        from app.request_processing.parser import HTTPRequest

        requests = []
        with open(jsonl_path) as f:
            for line in f:
                data = json.loads(line.strip())
                requests.append(self._dict_to_request(data))

        # Extract features
        feature_matrix = self.feature_pipeline.extract_batch(requests)
        return self.train_from_features(feature_matrix)

    def save(self, path: str):
        """Save the trained model."""
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.model.save(path)
        print(f"Model saved to {path}")

    def load(self, path: str):
        """Load a trained model."""
        self.model.load(path)
        print(f"Model loaded from {path}")

    def _dict_to_request(self, data: dict) -> HTTPRequest:
        """Convert a dictionary to an HTTPRequest."""
        return HTTPRequest(
            request_id=data.get("request_id", "IMPORTED"),
            source_id=data.get("source_id", "IMPORTED"),
            method=data.get("method", "GET"),
            path=data.get("path", "/"),
            query=data.get("query", {}),
            query_string=data.get("query_string", ""),
            headers=data.get("headers", {}),
            body_fields=data.get("body_fields", []),
            body_size=data.get("body_size", 0),
            session_id=data.get("session_id", "IMPORTED"),
            content_type=data.get("content_type", ""),
            user_agent=data.get("user_agent", ""),
        )
