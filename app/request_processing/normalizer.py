"""Request Normalizer - standardizes parsed HTTP requests."""

import re
import unicodedata
from typing import Optional


class RequestNormalizer:
    """Normalizes HTTP request data for consistent feature extraction."""

    # Common encoding patterns
    URL_ENCODED_PATTERNS = [
        (r"%[0-9a-fA-F]{2}", "URL_ENCODED"),
        (r"\\u[0-9a-fA-F]{4}", "UNICODE"),
        (r"&#\d+;", "HTML_ENTITY"),
        (r"&#x[0-9a-fA-F]+;", "HEX_ENTITY"),
    ]

    def normalize_method(self, method: str) -> str:
        """Normalize HTTP method to uppercase."""
        return method.strip().upper()

    def normalize_path(self, path: str) -> str:
        """Normalize URL path."""
        if not path:
            return "/"

        # Decode unicode
        path = unicodedata.normalize("NFKC", path)

        # Remove null bytes
        path = path.replace("\x00", "")

        # Decode common URL encoding for normalization
        # but keep the original query string for feature extraction

        # Normalize double slashes (except leading)
        if path.startswith("//"):
            path = "/" + path.lstrip("/")

        # Remove trailing slash (except root)
        if path != "/" and path.endswith("/"):
            path = path.rstrip("/")

        return path

    def normalize_query(self, query: dict) -> dict:
        """Normalize query parameters."""
        normalized = {}
        for key, value in query.items():
            if isinstance(value, list):
                normalized[key] = value
            else:
                normalized[key] = [value]
        return normalized

    def normalize_headers(self, headers: dict) -> dict:
        """Normalize HTTP headers."""
        normalized = {}
        for key, value in headers.items():
            normalized[key.lower()] = value
        return normalized

    def detect_encoding(self, text: str) -> list[str]:
        """Detect encoding patterns in text."""
        encodings = []
        for pattern, encoding_type in self.URL_ENCODED_PATTERNS:
            if re.search(pattern, text):
                encodings.append(encoding_type)
        return encodings

    def compute_encoding_ratio(self, text: str) -> float:
        """Calculate ratio of encoded characters in text."""
        if not text:
            return 0.0

        url_encoded = len(re.findall(r"%[0-9a-fA-F]{2}", text))
        unicode_encoded = len(re.findall(r"\\u[0-9a-fA-F]{4}", text))
        total_encoded = url_encoded + unicode_encoded

        return min(1.0, total_encoded / max(1, len(text)))
