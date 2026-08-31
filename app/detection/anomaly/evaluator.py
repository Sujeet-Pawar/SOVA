"""Anomaly Model Evaluator - evaluates anomaly detection performance."""

import numpy as np
from typing import Optional
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    classification_report,
)
from app.feature_engine.pipeline import FeaturePipeline
from app.detection.anomaly.model import AnomalyModel


class AnomalyEvaluator:
    """Evaluates anomaly detection model performance."""

    def __init__(self):
        self.feature_pipeline = FeaturePipeline()

    def evaluate(
        self,
        model: AnomalyModel,
        normal_features: np.ndarray,
        attack_features: Optional[np.ndarray] = None,
    ) -> dict:
        """Evaluate the anomaly model on test data.

        Args:
            model: Trained anomaly model
            normal_features: Feature matrix of normal traffic
            attack_features: Feature matrix of attack traffic (if available)

        Returns:
            Dictionary of evaluation metrics
        """
        # Score normal traffic
        normal_scores = model.score(normal_features)
        normal_predictions = model.predict(normal_features)

        results = {
            "normal_samples": len(normal_features),
            "normal_mean_score": float(np.mean(normal_scores)),
            "normal_median_score": float(np.median(normal_scores)),
            "normal_max_score": float(np.max(normal_scores)),
            "normal_detection_rate": float(np.mean(normal_predictions == -1)),
        }

        if attack_features is not None and len(attack_features) > 0:
            # Score attack traffic
            attack_scores = model.score(attack_features)
            attack_predictions = model.predict(attack_features)

            results["attack_samples"] = len(attack_features)
            results["attack_mean_score"] = float(np.mean(attack_scores))
            results["attack_median_score"] = float(np.median(attack_scores))
            results["attack_min_score"] = float(np.min(attack_scores))
            results["attack_detection_rate"] = float(np.mean(attack_predictions == -1))

            # Combined metrics (attack = 1, normal = 0)
            y_true = np.concatenate([
                np.zeros(len(normal_features)),
                np.ones(len(attack_features)),
            ])
            y_pred = np.concatenate([
                normal_predictions == -1,
                attack_predictions == -1,
            ])
            y_scores = np.concatenate([normal_scores, attack_scores])

            # Binary classification metrics
            results["precision"] = float(precision_score(y_true, y_pred, zero_division=0))
            results["recall"] = float(recall_score(y_true, y_pred, zero_division=0))
            results["f1"] = float(f1_score(y_true, y_pred, zero_division=0))

            try:
                results["roc_auc"] = float(roc_auc_score(y_true, y_scores))
            except ValueError:
                results["roc_auc"] = 0.0

        return results

    def evaluate_thresholds(
        self,
        model: AnomalyModel,
        normal_features: np.ndarray,
        attack_features: Optional[np.ndarray] = None,
        thresholds: Optional[list[float]] = None,
    ) -> dict:
        """Evaluate model at different thresholds."""
        if thresholds is None:
            thresholds = [0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]

        results = {}
        for threshold in thresholds:
            # Temporarily change threshold
            old_threshold = model.model.contamination
            # We evaluate by directly comparing scores to threshold
            normal_scores = model.score(normal_features)
            normal_detected = np.mean(normal_scores >= threshold)

            metrics = {
                "threshold": threshold,
                "normal_false_positive_rate": float(normal_detected),
            }

            if attack_features is not None and len(attack_features) > 0:
                attack_scores = model.score(attack_features)
                attack_detected = np.mean(attack_scores >= threshold)
                metrics["attack_detection_rate"] = float(attack_detected)

            results[f"threshold_{threshold}"] = metrics

        return results
