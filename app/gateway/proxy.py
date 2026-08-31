"""SOVA-WAF Gateway - Reverse Proxy.

Listens on http://127.0.0.1:8443
Forwards to backend http://127.0.0.1:8080
"""

import sys
import os
import yaml
import time
from datetime import datetime
from pathlib import Path

import httpx
from fastapi import FastAPI, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app.request_processing.parser import RequestParser, HTTPRequest
from app.request_processing.normalizer import RequestNormalizer
from app.request_processing.sanitizer import RequestSanitizer
from app.feature_engine.pipeline import FeaturePipeline
from app.detection.rules.base import RuleEngine
from app.detection.anomaly.detector import AnomalyDetector
from app.detection.behavioral.detector import BehavioralDetector
from app.detection.common.models import SecuritySignals, ThreatType
from app.enforcement.block import EnforcementEngine
from app.logging_service.request_logger import RequestLogger
from app.logging_service.security_logger import SecurityLogger
from app.gateway.websocket_manager import ws_manager


def load_config() -> dict:
    """Load configuration from config.yaml."""
    config_path = PROJECT_ROOT / "config" / "config.yaml"
    if config_path.exists():
        with open(config_path) as f:
            return yaml.safe_load(f)
    return {}


config = load_config()

app = FastAPI(title="SOVA-WAF Gateway", version="0.1.0")

# CORS for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173", "http://localhost:5174"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API routes for frontend
from app.gateway.api_routes import router as api_router
from app.gateway.export_routes import router as export_router
from app.gateway.training_routes import router as training_router
app.include_router(api_router)
app.include_router(export_router)
app.include_router(training_router)

# Backend configuration
BACKEND_HOST = os.getenv("SOVA_BACKEND_HOST", config.get("backend", {}).get("host", "127.0.0.1"))
BACKEND_PORT = int(os.getenv("SOVA_BACKEND_PORT", config.get("backend", {}).get("port", 8080)))
BACKEND_URL = f"http://{BACKEND_HOST}:{BACKEND_PORT}"

# Initialize components
parser = RequestParser()
normalizer = RequestNormalizer()
sanitizer = RequestSanitizer()
feature_pipeline = FeaturePipeline()
rule_engine = RuleEngine()
anomaly_detector = AnomalyDetector()
behavioral_detector = BehavioralDetector()
enforcement_engine = EnforcementEngine(config.get("enforcement", {}))
request_logger = RequestLogger()
security_logger = SecurityLogger(config.get("logging", {}))

# HTTP client for forwarding
http_client = httpx.AsyncClient(timeout=30.0)


# Paths to skip WAF processing (handled by FastAPI routes directly)
SKIP_PATHS = {"/health", "/ws"}
SKIP_PREFIXES = ("/api/", "/docs", "/openapi")


# ─── Raw ASGI middleware (avoids Starlette HTTPMiddleware eating WebSocket upgrades) ───

class WAFMiddleware:
    """Raw ASGI middleware that skips WebSocket connections entirely.

    Starlette's @app.middleware("http") wraps ALL connections including WebSockets,
    which breaks the WebSocket handshake.  This raw ASGI middleware checks scope["type"]
    first and only processes plain HTTP requests through the WAF pipeline.
    """

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        # Let WebSocket connections pass through untouched
        if scope["type"] == "websocket":
            await self.app(scope, receive, send)
            return

        # Skip WAF for internal API routes, health checks, and CORS preflight
        path = scope.get("path", "")
        method = scope.get("method", "")
        if path in SKIP_PATHS or path.startswith(SKIP_PREFIXES) or method == "OPTIONS":
            await self.app(scope, receive, send)
            return

        # Run the WAF pipeline for normal HTTP requests
        request = Request(scope, receive)
        response = await _process_waf(request)
        await response(scope, receive, send)


async def _process_waf(request: Request) -> Response:
    """Process a single HTTP request through the full WAF detection pipeline."""
    start_time = time.time()

    # Read request body
    body = await request.body()

    # Get query string
    query_string = str(request.url.query) if request.url.query else ""

    # Parse request into internal model
    http_request = parser.parse(
        method=request.method,
        path=str(request.url.path),
        headers=dict(request.headers),
        query_string=query_string,
        body=body,
        source_id=request.client.host if request.client else "UNKNOWN",
        session_id=request.headers.get("x-session-id", request.client.host if request.client else "UNKNOWN"),
        remote_addr=request.client.host if request.client else "UNKNOWN",
    )

    # Normalize
    http_request.path = normalizer.normalize_path(http_request.path)
    http_request.method = normalizer.normalize_method(http_request.method)
    http_request.headers = normalizer.normalize_headers(http_request.headers)

    # Sanitize
    http_request = sanitizer.sanitize(http_request)

    # Log request
    request_logger.log_request(http_request)

    try:
        # Feature extraction
        feature_vector = feature_pipeline.extract(http_request)

        # Rule detection
        rule_results = rule_engine.analyze(http_request)

        # Anomaly detection
        anomaly_result = anomaly_detector.detect(feature_vector)

        # Behavioral detection
        behavioral_result = behavioral_detector.detect(http_request)

        # Combine signals
        security_signals = _build_security_signals(
            rule_results, anomaly_result, behavioral_result
        )

        # Enforcement decision
        action = enforcement_engine.decide(security_signals)
        security_signals.action = action

        # Log security event if threat detected
        if action != "ALLOW":
            security_logger.log_event(http_request, security_signals)

        latency_ms = round((time.time() - start_time) * 1000, 2)

        # Broadcast detection event over WebSocket
        await _broadcast_detection(
            http_request, security_signals, action, rule_results,
            anomaly_result, behavioral_result, latency_ms
        )

        # Execute decision
        if action == "BLOCK":
            request_logger.log_response(http_request, 403, latency_ms)
            return JSONResponse(
                status_code=403,
                content={"error": "Blocked by SOVA-WAF", "request_id": http_request.request_id}
            )

        # ALLOW or FLAG - forward to backend
        response = await _forward_request(request, body, http_request)

        request_logger.log_response(http_request, response.status_code, latency_ms)

        return response

    except Exception as e:
        # On error, still forward the request (fail-open)
        latency_ms = round((time.time() - start_time) * 1000, 2)
        request_logger.log_response(http_request, 500, latency_ms)
        return JSONResponse(
            status_code=502,
            content={"error": "Gateway error", "detail": str(e)}
        )


async def _forward_request(
    original_request: Request, body: bytes, http_request: HTTPRequest
) -> Response:
    """Forward the request to the backend application."""
    # Build backend URL
    backend_url = f"{BACKEND_URL}{original_request.url.path}"
    if original_request.url.query:
        backend_url += f"?{original_request.url.query}"

    # Forward headers (excluding host and transfer-encoding)
    headers = {}
    for key, value in original_request.headers.items():
        if key.lower() not in ("host", "transfer-encoding"):
            headers[key] = value

    # Add WAF metadata headers
    headers["x-sova-request-id"] = http_request.request_id
    headers["x-sova-source"] = http_request.source_id

    try:
        response = await http_client.request(
            method=http_request.method,
            url=backend_url,
            headers=headers,
            content=body if body else None,
        )

        # Build FastAPI response
        response_headers = dict(response.headers)
        # Remove hop-by-hop headers
        for h in ("transfer-encoding", "connection", "keep-alive"):
            response_headers.pop(h, None)

        return Response(
            content=response.content,
            status_code=response.status_code,
            headers=response_headers,
        )
    except httpx.ConnectError:
        return JSONResponse(
            status_code=502,
            content={"error": "Backend application is not reachable"}
        )


def _build_security_signals(
    rule_results, anomaly_result, behavioral_result
) -> SecuritySignals:
    """Combine all detection results into SecuritySignals."""
    signals = SecuritySignals()

    # Rule signals
    if rule_results:
        signals.known_threat_score = max(r.score for r in rule_results)
        signals.detected_threats = [r for r in rule_results if r.score > 0]
        for result in rule_results:
            if result.threat_type != ThreatType.NONE:
                signals.explanations.append(
                    f"{result.detector}: {result.reason}"
                )

    # Anomaly signals
    if anomaly_result:
        signals.anomaly_score = anomaly_result.anomaly_score
        if anomaly_result.classification == "ANOMALOUS":
            signals.explanations.append(anomaly_result.reason)

    # Behavioral signals
    if behavioral_result:
        signals.behavior_score = behavioral_result.behavior_score
        if behavioral_result.classification == "SUSPICIOUS":
            signals.explanations.append(behavioral_result.reason)

    return signals


async def _broadcast_detection(
    http_request, security_signals, action, rule_results,
    anomaly_result, behavioral_result, latency_ms
):
    """Broadcast a detection event to all WebSocket clients."""
    try:
        rule_result_list = []
        for r in rule_results:
            rule_result_list.append({
                "detector": r.detector,
                "threat_type": r.threat_type.value if hasattr(r.threat_type, 'value') else str(r.threat_type),
                "score": round(r.score, 4),
                "confidence": round(r.confidence, 4),
                "reason": r.reason,
                "evidence": r.evidence[:5],
            })

        threat_type = "NONE"
        if rule_results:
            for r in rule_results:
                tt = r.threat_type.value if hasattr(r.threat_type, 'value') else str(r.threat_type)
                if tt != "NONE":
                    threat_type = tt
                    break

        await ws_manager.broadcast_detection(
            request_id=http_request.request_id,
            method=http_request.method,
            path=http_request.path,
            source_id=http_request.source_id,
            action=action,
            rule_score=round(security_signals.known_threat_score, 4),
            anomaly_score=round(security_signals.anomaly_score, 4),
            behavior_score=round(security_signals.behavior_score, 4),
            threat_type=threat_type,
            rule_results=rule_result_list,
            anomaly_classification=anomaly_result.classification if anomaly_result else "UNKNOWN",
            behavioral_classification=behavioral_result.classification if behavioral_result else "UNKNOWN",
            explanations=security_signals.explanations[:10],
            latency_ms=latency_ms,
        )
    except Exception:
        pass  # Don't break the pipeline if WebSocket fails


# ─── Add middleware AFTER app creation so it wraps routes ───
app.add_middleware(WAFMiddleware)


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time detection event streaming."""
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep connection alive; clients may send pings
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        await ws_manager.disconnect(websocket)
    except Exception:
        await ws_manager.disconnect(websocket)


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "SOVA-WAF", "version": "0.1.0"}


if __name__ == "__main__":
    import uvicorn

    host = os.getenv("SOVA_GATEWAY_HOST", config.get("gateway", {}).get("host", "127.0.0.1"))
    port = int(os.getenv("SOVA_GATEWAY_PORT", config.get("gateway", {}).get("port", 8443)))

    print(f"SOVA-WAF Gateway starting on http://{host}:{port}")
    print(f"Backend target: {BACKEND_URL}")
    uvicorn.run(app, host=host, port=port)
