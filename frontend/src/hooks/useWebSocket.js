import { useEffect, useRef, useCallback, useState } from "react";

const WS_URL = "ws://127.0.0.1:8443/ws";
const RECONNECT_DELAY = 2000;
const PING_INTERVAL = 15000;

/**
 * Hook that maintains a WebSocket connection to the SOVA-WAF gateway
 * and provides real-time detection events.
 *
 * Returns { events, stats, connected, clearEvents }
 */
export function useWebSocket() {
  const wsRef = useRef(null);
  const [events, setEvents] = useState([]);
  const [stats, setStats] = useState({
    total_requests: 0,
    allowed: 0,
    flagged: 0,
    blocked: 0,
    threat_counts: {},
    detection_rate: 0,
  });
  const [connected, setConnected] = useState(false);
  const reconnectTimer = useRef(null);
  const pingTimer = useRef(null);

  const connect = useCallback(() => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) return;

    const ws = new WebSocket(WS_URL);
    wsRef.current = ws;

    ws.onopen = () => {
      setConnected(true);
      // Start pinging to keep alive
      pingTimer.current = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) {
          ws.send("ping");
        }
      }, PING_INTERVAL);
    };

    ws.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data);

        if (msg.type === "detection") {
          setEvents((prev) => {
            const next = [
              {
                ...msg,
                timestamp: new Date().toISOString(),
              },
              ...prev,
            ];
            // Keep last 200 events in memory
            return next.slice(0, 200);
          });

          // Update running stats
          setStats((prev) => {
            const total = prev.total_requests + 1;
            const allowed =
              prev.allowed + (msg.action === "ALLOW" ? 1 : 0);
            const flagged =
              prev.flagged + (msg.action === "FLAG" ? 1 : 0);
            const blocked =
              prev.blocked + (msg.action === "BLOCK" ? 1 : 0);

            const threatCounts = { ...prev.threat_counts };
            if (msg.threat_type && msg.threat_type !== "NONE") {
              threatCounts[msg.threat_type] =
                (threatCounts[msg.threat_type] || 0) + 1;
            }

            return {
              total_requests: total,
              allowed,
              flagged,
              blocked,
              threat_counts: threatCounts,
              detection_rate:
                total > 0
                  ? Math.round(((flagged + blocked) / total) * 10000) /
                    100
                  : 0,
            };
          });
        } else if (msg.type === "stats_update") {
          setStats(msg);
        }
      } catch {
        // ignore parse errors
      }
    };

    ws.onclose = () => {
      setConnected(false);
      if (pingTimer.current) clearInterval(pingTimer.current);
      // Reconnect after delay
      reconnectTimer.current = setTimeout(connect, RECONNECT_DELAY);
    };

    ws.onerror = () => {
      ws.close();
    };
  }, []);

  useEffect(() => {
    connect();
    return () => {
      if (wsRef.current) wsRef.current.close();
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current);
      if (pingTimer.current) clearInterval(pingTimer.current);
    };
  }, [connect]);

  const clearEvents = useCallback(() => setEvents([]), []);

  return { events, stats, connected, clearEvents };
}
