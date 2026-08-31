"""Request Feature Extraction - extracts HTTP request-level features."""

import math
from typing import Optional
from app.request_processing.parser import HTTPRequest


class RequestFeatureExtractor:
    """Extracts features directly from HTTP request properties."""

    METHOD_MAP = {
        "GET": 0,
        "POST": 1,
        "PUT": 2,
        "DELETE": 3,
        "PATCH": 4,
        "HEAD": 5,
        "OPTIONS": 6,
    }

    def extract(self, request: HTTPRequest) -> dict:
        """Extract request-level features from an HTTPRequest."""
        features = {}

        # Method encoding
        features["method_encoded"] = self.METHOD_MAP.get(request.method, -1)

        # URL length features
        features["url_length"] = request.url_length
        features["path_length"] = request.path_length
        features["query_length"] = request.query_length
        features["body_length"] = request.body_size

        # Parameter counts
        features["parameter_count"] = len(request.query)
        features["header_count"] = len(request.headers)
        features["body_field_count"] = len(request.body_fields)

        # URL depth (number of path segments)
        features["url_depth"] = len([s for s in request.path.split("/") if s])

        # Path features
        features["path_has_extension"] = 1 if "." in request.path.split("/")[-1] else 0
        features["path_has_query"] = 1 if request.query_string else 0

        # Header features
        features["has_content_type"] = 1 if request.content_type else 0
        features["has_user_agent"] = 1 if request.user_agent else 0

        return features

    def get_feature_names(self) -> list[str]:
        """Return ordered list of feature names."""
        return [
            "method_encoded",
            "url_length",
            "path_length",
            "query_length",
            "body_length",
            "parameter_count",
            "header_count",
            "body_field_count",
            "url_depth",
            "path_has_extension",
            "path_has_query",
            "has_content_type",
            "has_user_agent",
        ]
