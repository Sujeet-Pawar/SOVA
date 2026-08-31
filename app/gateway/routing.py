"""Request Routing - determines how requests are routed through the WAF."""

from typing import Optional
from app.request_processing.parser import HTTPRequest


class RequestRouter:
    """Routes requests through appropriate processing paths."""

    # Paths that require strict checking
    HIGH_RISK_PATHS = {"/admin", "/upload", "/login"}

    # Paths that can be processed quickly
    LOW_RISK_PATHS = {"/health", "/static"}

    def __init__(self):
        self.path_risk_map = {}

    def get_risk_level(self, request: HTTPRequest) -> str:
        """Determine risk level of a request based on its characteristics."""
        path = request.path.lower()

        # High-risk paths
        if path in self.HIGH_RISK_PATHS:
            return "HIGH"

        # Admin endpoints
        if "/admin" in path:
            return "HIGH"

        # File operations
        if "/upload" in path or "/download" in path:
            return "HIGH"

        # Login/auth endpoints
        if "/login" in path or "/auth" in path:
            return "HIGH"

        # Low-risk static content
        if any(path.endswith(ext) for ext in [".css", ".js", ".png", ".jpg", ".ico"]):
            return "LOW"

        # Default to medium
        return "MEDIUM"

    def should_apply_full_pipeline(self, request: HTTPRequest) -> bool:
        """Determine if the full detection pipeline should be applied."""
        risk = self.get_risk_level(request)
        return risk in ("HIGH", "MEDIUM")

    def get_processing_config(self, request: HTTPRequest) -> dict:
        """Get processing configuration for this request."""
        risk = self.get_risk_level(request)

        return {
            "risk_level": risk,
            "apply_rules": True,
            "apply_anomaly": True,
            "apply_behavioral": risk == "HIGH",
            "log_level": "VERBOSE" if risk == "HIGH" else "STANDARD",
        }
