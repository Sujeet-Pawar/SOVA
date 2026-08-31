"""Tests for Anomaly Detection."""

import pytest
import numpy as np
from app.request_processing.parser import HTTPRequest
from app.feature_engine.pipeline import FeaturePipeline
from app.detection.anomaly.model import AnomalyModel
from app.detection.anomaly.detector import AnomalyDetector


class TestAnomalyModel:
    """Test the Isolation Forest model wrapper."""

    def test_train_and_predict(self):
        """Test training and prediction."""
        model = AnomalyModel(contamination=0.1, random_state=42)
        np.random.seed(42)
        normal_data = np.random.randn(200, 5) * 0.5
        model.train(normal_data)
        assert model.is_trained

        predictions = model.predict(normal_data[:10])
        assert len(predictions) == 10
        assert np.sum(predictions == 1) > 0

    def test_anomaly_score(self):
        """Test anomaly scoring - anomalous data scores higher than normal."""
        model = AnomalyModel(contamination=0.1, random_state=42)
        np.random.seed(42)
        normal_data = np.random.randn(200, 5) * 0.5
        model.train(normal_data)

        scores = model.score(normal_data[:10])
        assert len(scores) == 10
        assert all(0 <= s <= 1 for s in scores)

        # Clearly anomalous data (far from training distribution)
        anomalous_data = np.array([[100, 100, 100, 100, 100]])
        anomaly_score = model.score(anomalous_data)
        normal_mean = np.mean(model.score(normal_data[:50]))
        assert anomaly_score[0] > normal_mean, "Anomalous data should score higher"

    def test_save_and_load(self, tmp_path):
        """Test model save and load."""
        model = AnomalyModel(contamination=0.1, random_state=42)
        np.random.seed(42)
        normal_data = np.random.randn(100, 5)
        model.train(normal_data)

        save_path = str(tmp_path / "test_model.joblib")
        model.save(save_path)

        model2 = AnomalyModel()
        model2.load(save_path)
        assert model2.is_trained

        scores1 = model.score(normal_data[:5])
        scores2 = model2.score(normal_data[:5])
        np.testing.assert_array_almost_equal(scores1, scores2)


class TestAnomalyDetector:
    """Test the real-time anomaly detector."""

    def setup_method(self):
        self.pipeline = FeaturePipeline()

    def test_detector_without_model(self):
        """Test detector behavior without trained model."""
        detector = AnomalyDetector(model_path="/nonexistent/path/to/model.joblib")
        request = HTTPRequest(method="GET", path="/")
        fv = self.pipeline.extract(request)
        result = detector.detect(fv)
        assert result.anomaly_score >= 0

    def test_detector_with_trained_model(self, tmp_path):
        """Test detector with a trained model."""
        model = AnomalyModel(contamination=0.1, random_state=42)
        np.random.seed(42)
        n_features = len(self.pipeline.get_feature_names())
        normal_data = np.random.randn(100, n_features)
        model.train(normal_data)

        model_path = str(tmp_path / "test_model.joblib")
        model.save(model_path)

        detector = AnomalyDetector(model_path=model_path, threshold=0.6)
        request = HTTPRequest(method="GET", path="/", session_id="TEST")
        fv = self.pipeline.extract(request)

        result = detector.detect(fv)
        assert result.anomaly_score >= 0
        assert result.classification in ("NORMAL", "ANOMALOUS", "UNKNOWN")

    def test_model_detects_clear_anomalies(self, tmp_path):
        """Test that the model detects clearly anomalous synthetic data."""
        model = AnomalyModel(contamination=0.1, random_state=42)
        np.random.seed(42)

        # Train on tight normal distribution
        normal_data = np.random.randn(200, 5) * 0.1
        model.train(normal_data)

        # Clearly anomalous point
        anomalous_point = np.array([[100, 100, 100, 100, 100]])
        anomaly_score = model.score(anomalous_point)

        # This should score very high (highly anomalous)
        assert anomaly_score[0] > 0.5, f"Anomaly score should be high, got {anomaly_score[0]}"
