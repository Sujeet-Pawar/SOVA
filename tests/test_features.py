"""Tests for Feature Extraction Pipeline."""

import pytest
import numpy as np
from app.request_processing.parser import HTTPRequest
from app.feature_engine.pipeline import FeaturePipeline
from app.feature_engine.request_features import RequestFeatureExtractor
from app.feature_engine.structural_features import StructuralFeatureExtractor
from app.feature_engine.behavioral_features import BehavioralFeatureExtractor


class TestRequestFeatures:
    """Test request feature extraction."""

    def setup_method(self):
        self.extractor = RequestFeatureExtractor()

    def test_extract_basic_features(self):
        """Test basic feature extraction."""
        request = HTTPRequest(
            method="GET",
            path="/search",
            query={"q": ["laptop"]},
            query_string="q=laptop",
            headers={"user-agent": "Test/1.0"},
            body_size=0,
        )
        request.compute_lengths()

        features = self.extractor.extract(request)

        assert "method_encoded" in features
        assert "url_length" in features
        assert "path_length" in features
        assert features["method_encoded"] == 0  # GET = 0
        assert features["path_length"] == len("/search")

    def test_post_method_encoded(self):
        """Test POST method encoding."""
        request = HTTPRequest(method="POST", path="/login")
        request.compute_lengths()

        features = self.extractor.extract(request)
        assert features["method_encoded"] == 1  # POST = 1

    def test_feature_names_count(self):
        """Test feature names match extraction."""
        names = self.extractor.get_feature_names()
        request = HTTPRequest(method="GET", path="/test")
        request.compute_lengths()
        features = self.extractor.extract(request)

        assert len(names) == len(features)


class TestStructuralFeatures:
    """Test structural feature extraction."""

    def setup_method(self):
        self.extractor = StructuralFeatureExtractor()

    def test_special_char_ratio(self):
        """Test special character ratio calculation."""
        request = HTTPRequest(
            path="/search",
            query_string="q=test;script",
        )

        features = self.extractor.extract(request)
        assert "special_char_ratio" in features
        assert 0 <= features["special_char_ratio"] <= 1

    def test_entropy(self):
        """Test entropy calculation."""
        request = HTTPRequest(path="/test", query_string="hello=world")

        features = self.extractor.extract(request)
        assert "entropy" in features
        assert features["entropy"] > 0

    def test_traversal_indicator(self):
        """Test path traversal detection in features."""
        request = HTTPRequest(path="/../../../etc/passwd")

        features = self.extractor.extract(request)
        assert features["path_traversal_dots"] == 1

    def test_empty_request(self):
        """Test features for empty request."""
        request = HTTPRequest(path="/", query_string="")
        features = self.extractor.extract(request)

        assert features["encoding_ratio"] == 0.0
        assert features["entropy"] == 0.0 or features["entropy"] >= 0


class TestBehavioralFeatures:
    """Test behavioral feature extraction."""

    def setup_method(self):
        self.extractor = BehavioralFeatureExtractor()

    def test_first_request_features(self):
        """Test features for first request from a session."""
        request = HTTPRequest(
            session_id="TEST_SESSION",
            path="/",
            method="GET",
        )

        features = self.extractor.extract(request)
        assert features["request_count_10s"] == 1
        assert features["unique_endpoint_count"] == 1
        assert features["failed_request_count"] == 0

    def test_repeated_endpoint(self):
        """Test repeated endpoint counting."""
        session_id = "REPEAT_SESSION"

        # First request
        req1 = HTTPRequest(session_id=session_id, path="/test", method="GET")
        self.extractor.extract(req1)

        # Second request to same endpoint
        req2 = HTTPRequest(session_id=session_id, path="/test", method="GET")
        features = self.extractor.extract(req2)

        assert features["repeated_endpoint_count"] == 1

    def test_multiple_endpoints(self):
        """Test unique endpoint tracking."""
        session_id = "MULTI_SESSION"

        for path in ["/", "/search", "/products"]:
            req = HTTPRequest(session_id=session_id, path=path, method="GET")
            self.extractor.extract(req)

        req = HTTPRequest(session_id=session_id, path="/profile", method="GET")
        features = self.extractor.extract(req)
        assert features["unique_endpoint_count"] == 4


class TestFeaturePipeline:
    """Test the complete feature pipeline."""

    def setup_method(self):
        self.pipeline = FeaturePipeline()

    def test_extract_complete_vector(self):
        """Test complete feature vector extraction."""
        request = HTTPRequest(
            method="GET",
            path="/search",
            query={"q": ["laptop"]},
            query_string="q=laptop",
            headers={"user-agent": "Test/1.0"},
            session_id="TEST_SESSION",
        )
        request.compute_lengths()

        fv = self.pipeline.extract(request)

        assert fv.values.shape[0] == len(self.pipeline.feature_names)
        assert all(np.isfinite(fv.values))

    def test_feature_names(self):
        """Test feature names are consistent."""
        names = self.pipeline.get_feature_names()
        assert len(names) > 20  # Should have many features
        assert "method_encoded" in names
        assert "entropy" in names
        assert "request_count_10s" in names

    def test_extract_batch(self):
        """Test batch feature extraction."""
        requests = [
            HTTPRequest(method="GET", path="/", session_id="BATCH1"),
            HTTPRequest(method="POST", path="/login", session_id="BATCH2"),
            HTTPRequest(method="GET", path="/search", session_id="BATCH3"),
        ]

        matrix = self.pipeline.extract_batch(requests)
        assert matrix.shape[0] == 3
        assert matrix.shape[1] == len(self.pipeline.feature_names)
