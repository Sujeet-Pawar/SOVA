"""Feature Pipeline - combines all feature extractors into a unified feature vector."""

import numpy as np
from typing import Optional
from app.request_processing.parser import HTTPRequest
from app.feature_engine.request_features import RequestFeatureExtractor
from app.feature_engine.structural_features import StructuralFeatureExtractor
from app.feature_engine.behavioral_features import BehavioralFeatureExtractor


class FeatureVector:
    """Represents the extracted feature vector from a request."""

    def __init__(self, features: dict, feature_names: list[str]):
        self.features = features
        self.feature_names = feature_names
        self.values = np.array([features.get(name, 0.0) for name in feature_names])

    def to_numpy(self) -> np.ndarray:
        """Return feature values as numpy array."""
        return self.values.copy()

    def to_dict(self) -> dict:
        """Return feature dict."""
        return dict(self.features)

    def __repr__(self):
        return f"FeatureVector(features={len(self.feature_names)}, values={self.values})"


class FeaturePipeline:
    """Unified feature extraction pipeline.

    Input: HTTPRequest
    Output: FeatureVector
    """

    def __init__(self):
        self.request_extractor = RequestFeatureExtractor()
        self.structural_extractor = StructuralFeatureExtractor()
        self.behavioral_extractor = BehavioralFeatureExtractor()

        # Combine all feature names
        self.feature_names = (
            self.request_extractor.get_feature_names()
            + self.structural_extractor.get_feature_names()
            + self.behavioral_extractor.get_feature_names()
        )

    def extract(self, request: HTTPRequest) -> FeatureVector:
        """Extract complete feature vector from an HTTPRequest."""
        # Extract from each sub-module
        request_features = self.request_extractor.extract(request)
        structural_features = self.structural_extractor.extract(request)
        behavioral_features = self.behavioral_extractor.extract(request)

        # Merge all features
        all_features = {}
        all_features.update(request_features)
        all_features.update(structural_features)
        all_features.update(behavioral_features)

        return FeatureVector(all_features, self.feature_names)

    def extract_batch(self, requests: list[HTTPRequest]) -> np.ndarray:
        """Extract feature vectors for a batch of requests."""
        vectors = []
        for request in requests:
            fv = self.extract(request)
            vectors.append(fv.to_numpy())
        return np.array(vectors)

    def get_feature_names(self) -> list[str]:
        """Return ordered list of all feature names."""
        return self.feature_names.copy()
