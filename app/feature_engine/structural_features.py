"""Structural Feature Extraction - payload structure analysis."""

import math
from typing import Optional
from app.request_processing.parser import HTTPRequest
from app.request_processing.normalizer import RequestNormalizer


class StructuralFeatureExtractor:
    """Extracts structural features from request payloads."""

    def __init__(self):
        self.normalizer = RequestNormalizer()

    def extract(self, request: HTTPRequest) -> dict:
        """Extract structural features from an HTTPRequest."""
        features = {}

        # Combine all analyzable text
        full_text = self._get_analyzable_text(request)

        # Special character ratio
        features["special_char_ratio"] = self._compute_special_char_ratio(full_text)

        # Digit ratio
        features["digit_ratio"] = self._compute_digit_ratio(full_text)

        # Encoding ratio
        features["encoding_ratio"] = self.normalizer.compute_encoding_ratio(
            request.query_string
        )

        # Entropy
        features["entropy"] = self._compute_entropy(full_text)

        # Parameter complexity
        features["parameter_complexity"] = self._compute_parameter_complexity(request)

        # Path anomaly indicators
        features["path_double_slash"] = 1 if "//" in request.path else 0
        features["path_traversal_dots"] = 1 if ".." in request.path else 0

        # Query string features
        features["query_has_special_chars"] = self._query_has_special(request.query_string)
        features["query_max_value_length"] = self._max_query_value_length(request.query)
        features["query_has_encoded_chars"] = 1 if "%" in request.query_string else 0

        return features

    def get_feature_names(self) -> list[str]:
        """Return ordered list of feature names."""
        return [
            "special_char_ratio",
            "digit_ratio",
            "encoding_ratio",
            "entropy",
            "parameter_complexity",
            "path_double_slash",
            "path_traversal_dots",
            "query_has_special_chars",
            "query_max_value_length",
            "query_has_encoded_chars",
        ]

    def _get_analyzable_text(self, request: HTTPRequest) -> str:
        """Combine all text fields for analysis."""
        parts = [
            request.path,
            request.query_string,
        ]
        return " ".join(parts)

    def _compute_special_char_ratio(self, text: str) -> float:
        """Calculate ratio of special characters."""
        if not text:
            return 0.0
        special = sum(1 for c in text if not c.isalnum() and not c.isspace())
        return special / len(text)

    def _compute_digit_ratio(self, text: str) -> float:
        """Calculate ratio of digits."""
        if not text:
            return 0.0
        digits = sum(1 for c in text if c.isdigit())
        return digits / len(text)

    def _compute_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text."""
        if not text:
            return 0.0

        freq = {}
        for c in text:
            freq[c] = freq.get(c, 0) + 1

        length = len(text)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)

        return round(entropy, 4)

    def _compute_parameter_complexity(self, request: HTTPRequest) -> float:
        """Calculate parameter complexity score."""
        if not request.query:
            return 0.0

        complexity = 0.0

        # Number of parameters
        complexity += len(request.query) * 0.1

        # Average parameter value length
        total_value_len = 0
        for key, values in request.query.items():
            if isinstance(values, list):
                total_value_len += sum(len(v) for v in values)
            else:
                total_value_len += len(str(values))

        if request.query:
            avg_value_len = total_value_len / len(request.query)
            complexity += min(1.0, avg_value_len / 100)

        # Parameters with special characters
        for key, values in request.query.items():
            check_values = values if isinstance(values, list) else [values]
            for v in check_values:
                if any(c in v for c in "';\"<>{}[]()\\"):
                    complexity += 0.3

        return min(1.0, complexity)

    def _query_has_special(self, query_string: str) -> int:
        """Check if query has suspicious special characters."""
        suspicious = {"'", "\"", ";", "--", "<", ">", "{", "}"}
        return 1 if any(c in query_string for c in suspicious) else 0

    def _max_query_value_length(self, query: dict) -> int:
        """Get the maximum length of query parameter values."""
        max_len = 0
        for key, values in query.items():
            if isinstance(values, list):
                for v in values:
                    max_len = max(max_len, len(v))
            else:
                max_len = max(max_len, len(str(values)))
        return max_len
