"""WebSocket connection manager for real-time event broadcasting."""

import json
import asyncio
from typing import Set, Dict, Any
from fastapi import WebSocket


class ConnectionManager:
    """Manages WebSocket connections and broadcasts events to all clients."""

    def __init__(self):
        self._connections: Set[WebSocket] = set()
        self._lock = asyncio.Lock()
        # Keep a buffer of recent events for newly connected clients
        self._recent_events: list = []
        self._max_buffer = 50

    async def connect(self, websocket: WebSocket):
        """Accept a new WebSocket connection."""
        await websocket.accept()
        async with self._lock:
            self._connections.add(websocket)
        # Send recent events buffer to the new client
        for event in self._recent_events:
            try:
                await websocket.send_json(event)
            except Exception:
                break

    async def disconnect(self, websocket: WebSocket):
        """Remove a WebSocket connection."""
        async with self._lock:
            self._connections.discard(websocket)

    async def broadcast(self, event_type: str, data: Dict[str, Any]):
        """Broadcast an event to all connected clients."""
        message = {
            "type": event_type,
            **data,
        }
        # Buffer recent events
        self._recent_events.append(message)
        if len(self._recent_events) > self._max_buffer:
            self._recent_events = self._recent_events[-self._max_buffer:]

        disconnected: list = []
        async with self._lock:
            connections_copy = list(self._connections)

        for connection in connections_copy:
            try:
                await connection.send_json(message)
            except Exception:
                disconnected.append(connection)

        # Clean up disconnected clients
        if disconnected:
            async with self._lock:
                for conn in disconnected:
                    self._connections.discard(conn)

    async def broadcast_detection(
        self,
        request_id: str,
        method: str,
        path: str,
        source_id: str,
        action: str,
        rule_score: float,
        anomaly_score: float,
        behavior_score: float,
        threat_type: str,
        rule_results: list,
        anomaly_classification: str,
        behavioral_classification: str,
        explanations: list,
        latency_ms: float,
    ):
        """Broadcast a detection event from the WAF pipeline."""
        event = {
            "request_id": request_id,
            "method": method,
            "path": path,
            "source_id": source_id,
            "action": action,
            "rule_score": rule_score,
            "anomaly_score": anomaly_score,
            "behavior_score": behavior_score,
            "threat_type": threat_type,
            "rule_results": rule_results,
            "anomaly_classification": anomaly_classification,
            "behavioral_classification": behavioral_classification,
            "explanations": explanations,
            "latency_ms": latency_ms,
        }
        await self.broadcast("detection", event)

    async def broadcast_stats_update(self, stats: Dict[str, Any]):
        """Broadcast updated stats to all clients."""
        await self.broadcast("stats_update", stats)

    @property
    def active_connections(self) -> int:
        return len(self._connections)


# Singleton instance
ws_manager = ConnectionManager()
