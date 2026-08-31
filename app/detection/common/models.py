"""Common detection models shared across all detectors."""

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field
from datetime import datetime


class ThreatType(str, Enum):
    """Supported threat types."""
    NONE = "NONE"
    SQL_INJECTION = "SQL_INJECTION"
    XSS = "XSS"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    MALFORMED = "MALFORMED"
    ANOMALOUS = "ANOMALOUS"
    BEHAVIORAL = "BEHAVIORAL"


class DetectionResult(BaseModel):
    """Standardized output from every detector."""
    detector: str
    threat_type: ThreatType = ThreatType.NONE
    score: float = Field(default=0.0, ge=0.0, le=1.0)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    reason: str = ""
    evidence: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class AnomalyResult(BaseModel):
    """Output from anomaly detector."""
    anomaly_score: float = Field(default=0.0, ge=0.0, le=1.0)
    classification: str = "NORMAL"
    reason: str = ""
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class BehavioralResult(BaseModel):
    """Output from behavioral detector."""
    behavior_score: float = Field(default=0.0, ge=0.0, le=1.0)
    classification: str = "NORMAL"
    reason: str = ""
    details: dict = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class SecuritySignals(BaseModel):
    """Combined security assessment from all detectors."""
    known_threat_score: float = 0.0
    anomaly_score: float = 0.0
    behavior_score: float = 0.0
    detected_threats: list[DetectionResult] = Field(default_factory=list)
    explanations: list[str] = Field(default_factory=list)
    action: str = "ALLOW"
    timestamp: datetime = Field(default_factory=datetime.utcnow)
