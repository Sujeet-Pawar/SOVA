import { useState, useMemo } from "react";
import {
  ShieldAlert,
  Download,
  FileText,
  Trash2,
} from "lucide-react";
import {
  exportEventsCSV,
  exportEventsJSON,
} from "../api";

export default function SecurityEvents({ events, clearEvents }) {
  const [exporting, setExporting] = useState(null);

  const handleExport = async (type) => {
    setExporting(type);
    try {
      if (type === "csv") await exportEventsCSV();
      else if (type === "json") await exportEventsJSON();
    } catch (e) {
      console.error("Export failed:", e);
    }
    setExporting(null);
  };

  // Threat breakdown from WebSocket events
  const threatBreakdown = useMemo(() => {
    const counts = {};
    events.forEach((e) => {
      const type = e.threat_type || "NONE";
      if (type !== "NONE") {
        counts[type] = (counts[type] || 0) + 1;
      }
    });
    return Object.entries(counts)
      .map(([type, count]) => ({ type, count }))
      .sort((a, b) => b.count - a.count);
  }, [events]);

  const blocked = events.filter((e) => e.action === "BLOCK").length;
  const flagged = events.filter((e) => e.action === "FLAG").length;
  const allowed = events.filter((e) => e.action === "ALLOW").length;

  return (
    <div>
      <div
        className="page-header"
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "flex-start",
        }}
      >
        <div>
          <h2>🛡️ Security Events</h2>
          <p>
            Real-time event stream — {events.length} events captured
          </p>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <button
            className="btn btn-outline"
            onClick={() => handleExport("csv")}
            disabled={exporting}
          >
            <span
              style={{ display: "flex", alignItems: "center", gap: 6 }}
            >
              <FileText size={14} />
              {exporting === "csv" ? "Exporting..." : "Export CSV"}
            </span>
          </button>
          <button
            className="btn btn-outline"
            onClick={() => handleExport("json")}
            disabled={exporting}
          >
            <span
              style={{ display: "flex", alignItems: "center", gap: 6 }}
            >
              <Download size={14} />
              {exporting === "json" ? "Exporting..." : "Export JSON"}
            </span>
          </button>
          <button
            className="btn btn-outline"
            onClick={clearEvents}
            title="Clear local event buffer"
          >
            <span
              style={{ display: "flex", alignItems: "center", gap: 6 }}
            >
              <Trash2 size={14} />
              Clear
            </span>
          </button>
        </div>
      </div>

      {/* Threat Breakdown Stats */}
      <div style={{ display: "flex", gap: 16, marginBottom: 24 }}>
        <div className="stat-card green" style={{ flex: 1 }}>
          <div className="label">Allowed</div>
          <div className="value">{allowed}</div>
        </div>
        <div className="stat-card yellow" style={{ flex: 1 }}>
          <div className="label">Flagged</div>
          <div className="value">{flagged}</div>
        </div>
        <div className="stat-card red" style={{ flex: 1 }}>
          <div className="label">Blocked</div>
          <div className="value">{blocked}</div>
        </div>
        {threatBreakdown.length > 0 && (
          <div className="stat-card" style={{ flex: 2 }}>
            <div className="label">Threat Types</div>
            <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginTop: 4 }}>
              {threatBreakdown.map((t) => (
                <span
                  key={t.type}
                  style={{
                    fontSize: 12,
                    padding: "2px 8px",
                    borderRadius: 4,
                    background: "rgba(239,68,68,0.15)",
                    color: "#ef4444",
                    fontWeight: 600,
                  }}
                >
                  {t.type.replace("_", " ")}: {t.count}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Events Table */}
      <div
        style={{
          background: "var(--bg-card)",
          border: "1px solid var(--border)",
          borderRadius: 12,
          overflow: "hidden",
        }}
      >
        {events.length === 0 ? (
          <div className="empty-state" style={{ padding: 60 }}>
            <ShieldAlert />
            <p>No events yet — send test requests to see events here</p>
          </div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table className="events-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Request ID</th>
                  <th>Method</th>
                  <th>Path</th>
                  <th>Action</th>
                  <th>Threat</th>
                  <th>Rule Score</th>
                  <th>Anomaly</th>
                  <th>Behavior</th>
                  <th>Latency</th>
                </tr>
              </thead>
              <tbody>
                {events.map((event, i) => (
                  <tr
                    key={event.request_id || i}
                    style={
                      i === 0
                        ? { animation: "fadeIn 0.3s ease" }
                        : {}
                    }
                  >
                    <td className="mono">
                      {event.timestamp
                        ? new Date(event.timestamp).toLocaleTimeString()
                        : "—"}
                    </td>
                    <td className="mono">
                      {event.request_id?.substring(0, 8) || "—"}
                    </td>
                    <td className="mono">{event.method}</td>
                    <td className="mono">{event.path}</td>
                    <td>
                      <span
                        className={`action-badge ${event.action}`}
                        style={{
                          fontSize: 10,
                          padding: "2px 8px",
                        }}
                      >
                        {event.action}
                      </span>
                    </td>
                    <td>
                      <span
                        className={`threat-tag ${event.threat_type}`}
                        style={{
                          fontSize: 10,
                          padding: "2px 8px",
                        }}
                      >
                        {event.threat_type?.replace("_", " ") ||
                          "NONE"}
                      </span>
                    </td>
                    <td className="mono">
                      {event.rule_score?.toFixed(3)}
                    </td>
                    <td className="mono">
                      {event.anomaly_score?.toFixed(3)}
                    </td>
                    <td className="mono">
                      {event.behavior_score?.toFixed(3)}
                    </td>
                    <td className="mono">{event.latency_ms}ms</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
