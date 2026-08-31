import { useState, useEffect, useMemo } from "react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
} from "recharts";
import {
  Shield,
  AlertTriangle,
  Ban,
  CheckCircle,
  TrendingUp,
  Download,
  FileText,
  FileJson,
  Wifi,
  WifiOff,
  Activity,
} from "lucide-react";
import {
  exportReportHTML,
  exportReportJSON,
  exportStatsJSON,
} from "../api";

const COLORS = {
  ALLOW: "#10b981",
  FLAG: "#f59e0b",
  BLOCK: "#ef4444",
};

export default function Dashboard({ events, stats }) {
  const [exporting, setExporting] = useState(null);

  const handleExport = async (type) => {
    setExporting(type);
    try {
      if (type === "report-html") await exportReportHTML();
      else if (type === "report-json") await exportReportJSON();
      else if (type === "stats-json") await exportStatsJSON();
    } catch (e) {
      console.error("Export failed:", e);
    }
    setExporting(null);
  };

  const total = stats?.total_requests || 0;

  // Build score history from WebSocket events (last 30)
  const scoreHistory = useMemo(() => {
    return events
      .slice(0, 30)
      .reverse()
      .map((e) => ({
        path: e.path?.substring(0, 15) || "",
        rule_score: e.rule_score || 0,
        anomaly_score: e.anomaly_score || 0,
        behavior_score: e.behavior_score || 0,
      }));
  }, [events]);

  const threatData = useMemo(() => {
    return Object.entries(stats?.threat_counts || {}).map(([name, value]) => ({
      name: name.replace("_", " "),
      value,
    }));
  }, [stats]);

  const actionPieData = useMemo(() => {
    return [
      { name: "ALLOW", value: stats?.allowed || 0 },
      { name: "FLAG", value: stats?.flagged || 0 },
      { name: "BLOCK", value: stats?.blocked || 0 },
    ].filter((d) => d.value > 0);
  }, [stats]);

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
          <h2 style={{ display: "flex", alignItems: "center", gap: 10 }}>
            Anomaly Detection Dashboard
            <Wifi size={18} color="#10b981" />
          </h2>
          <p>Real-time monitoring via WebSocket — no polling</p>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <button
            className="btn btn-outline"
            onClick={() => handleExport("report-html")}
            disabled={exporting}
            title="Download styled HTML report"
          >
            <span
              style={{ display: "flex", alignItems: "center", gap: 6 }}
            >
              <FileText size={14} />
              {exporting === "report-html" ? "Exporting..." : "Report HTML"}
            </span>
          </button>
          <button
            className="btn btn-outline"
            onClick={() => handleExport("report-json")}
            disabled={exporting}
            title="Download full report as JSON"
          >
            <span
              style={{ display: "flex", alignItems: "center", gap: 6 }}
            >
              <FileJson size={14} />
              {exporting === "report-json" ? "Exporting..." : "Report JSON"}
            </span>
          </button>
          <button
            className="btn btn-outline"
            onClick={() => handleExport("stats-json")}
            disabled={exporting}
            title="Download statistics as JSON"
          >
            <span
              style={{ display: "flex", alignItems: "center", gap: 6 }}
            >
              <Download size={14} />
              {exporting === "stats-json" ? "Exporting..." : "Stats JSON"}
            </span>
          </button>
        </div>
      </div>

      {/* Stat Cards */}
      <div className="stat-grid">
        <div className="stat-card blue">
          <div className="label">Total Requests</div>
          <div className="value">{total.toLocaleString()}</div>
          <div className="sub">Processed through WAF</div>
        </div>
        <div className="stat-card green">
          <div className="label">Allowed</div>
          <div className="value">
            {(stats?.allowed || 0).toLocaleString()}
          </div>
          <div className="sub">
            {total > 0
              ? ((stats?.allowed / total) * 100).toFixed(1)
              : 0}
            % of traffic
          </div>
        </div>
        <div className="stat-card yellow">
          <div className="label">Flagged</div>
          <div className="value">
            {(stats?.flagged || 0).toLocaleString()}
          </div>
          <div className="sub">Requires review</div>
        </div>
        <div className="stat-card red">
          <div className="label">Blocked</div>
          <div className="value">
            {(stats?.blocked || 0).toLocaleString()}
          </div>
          <div className="sub">Threats prevented</div>
        </div>
      </div>

      {/* Charts */}
      <div className="chart-grid">
        {/* Score Timeline */}
        <div className="chart-card">
          <h3>📈 Anomaly Score Timeline</h3>
          {scoreHistory.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={scoreHistory}>
                <defs>
                  <linearGradient
                    id="gradRule"
                    x1="0"
                    y1="0"
                    x2="0"
                    y2="1"
                  >
                    <stop
                      offset="5%"
                      stopColor="#3b82f6"
                      stopOpacity={0.3}
                    />
                    <stop
                      offset="95%"
                      stopColor="#3b82f6"
                      stopOpacity={0}
                    />
                  </linearGradient>
                  <linearGradient
                    id="gradAnomaly"
                    x1="0"
                    y1="0"
                    x2="0"
                    y2="1"
                  >
                    <stop
                      offset="5%"
                      stopColor="#f59e0b"
                      stopOpacity={0.3}
                    />
                    <stop
                      offset="95%"
                      stopColor="#f59e0b"
                      stopOpacity={0}
                    />
                  </linearGradient>
                  <linearGradient
                    id="gradBehavior"
                    x1="0"
                    y1="0"
                    x2="0"
                    y2="1"
                  >
                    <stop
                      offset="5%"
                      stopColor="#8b5cf6"
                      stopOpacity={0.3}
                    />
                    <stop
                      offset="95%"
                      stopColor="#8b5cf6"
                      stopOpacity={0}
                    />
                  </linearGradient>
                </defs>
                <XAxis
                  dataKey="path"
                  tick={{ fontSize: 10, fill: "#64748b" }}
                />
                <YAxis
                  domain={[0, 1]}
                  tick={{ fontSize: 10, fill: "#64748b" }}
                />
                <Tooltip
                  contentStyle={{
                    background: "#1a2236",
                    border: "1px solid #2a3550",
                    borderRadius: 8,
                    fontSize: 12,
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="rule_score"
                  stroke="#3b82f6"
                  fill="url(#gradRule)"
                  name="Rule Score"
                />
                <Area
                  type="monotone"
                  dataKey="anomaly_score"
                  stroke="#f59e0b"
                  fill="url(#gradAnomaly)"
                  name="Anomaly Score"
                />
                <Area
                  type="monotone"
                  dataKey="behavior_score"
                  stroke="#8b5cf6"
                  fill="url(#gradBehavior)"
                  name="Behavior Score"
                />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <div className="empty-state">
              <TrendingUp />
              <p>Send test requests to see score trends</p>
            </div>
          )}
        </div>

        {/* Action Distribution */}
        <div className="chart-card">
          <h3>🎯 Action Distribution</h3>
          {actionPieData.length > 0 ? (
            <div style={{ display: "flex", alignItems: "center" }}>
              <ResponsiveContainer width="60%" height={200}>
                <PieChart>
                  <Pie
                    data={actionPieData}
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={80}
                    dataKey="value"
                    stroke="none"
                  >
                    {actionPieData.map((entry) => (
                      <Cell
                        key={entry.name}
                        fill={COLORS[entry.name]}
                      />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      background: "#1a2236",
                      border: "1px solid #2a3550",
                      borderRadius: 8,
                      fontSize: 12,
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
              <div style={{ flex: 1 }}>
                {actionPieData.map((d) => (
                  <div
                    key={d.name}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 8,
                      marginBottom: 8,
                      fontSize: 13,
                    }}
                  >
                    <div
                      style={{
                        width: 10,
                        height: 10,
                        borderRadius: 2,
                        background: COLORS[d.name],
                      }}
                    />
                    <span style={{ color: "#94a3b8" }}>{d.name}</span>
                    <span
                      style={{ fontWeight: 600, marginLeft: "auto" }}
                    >
                      {d.value}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="empty-state">
              <CheckCircle />
              <p>No actions recorded yet</p>
            </div>
          )}
        </div>

        {/* Threat Types */}
        <div className="chart-card">
          <h3>🔥 Threat Types Detected</h3>
          {threatData.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={threatData}>
                <XAxis
                  dataKey="name"
                  tick={{ fontSize: 10, fill: "#64748b" }}
                />
                <YAxis tick={{ fontSize: 10, fill: "#64748b" }} />
                <Tooltip
                  contentStyle={{
                    background: "#1a2236",
                    border: "1px solid #2a3550",
                    borderRadius: 8,
                    fontSize: 12,
                  }}
                />
                <Bar
                  dataKey="value"
                  fill="#ef4444"
                  radius={[4, 4, 0, 0]}
                />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="empty-state">
              <AlertTriangle />
              <p>No threats detected yet</p>
            </div>
          )}
        </div>

        {/* Recent Activity - Live Stream */}
        <div className="chart-card">
          <h3 style={{ display: "flex", alignItems: "center", gap: 6 }}>
            ⏱️ Live Event Stream
            <span
              style={{
                fontSize: 10,
                background: "#10b981",
                color: "#000",
                padding: "2px 6px",
                borderRadius: 4,
                fontWeight: 700,
              }}
            >
              LIVE
            </span>
          </h3>
          {events.length > 0 ? (
            <div style={{ maxHeight: 200, overflowY: "auto" }}>
              {events.slice(0, 15).map((entry, i) => (
                <div
                  key={entry.request_id || i}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 10,
                    padding: "6px 0",
                    borderBottom: "1px solid rgba(42,53,80,0.5)",
                    fontSize: 12,
                    animation:
                      i === 0 ? "fadeIn 0.3s ease" : "none",
                  }}
                >
                  <span
                    className={`action-badge ${entry.action}`}
                    style={{ fontSize: 10, padding: "2px 6px" }}
                  >
                    {entry.action}
                  </span>
                  <span
                    style={{
                      fontFamily: "monospace",
                      color: "#94a3b8",
                    }}
                  >
                    {entry.method} {entry.path}
                  </span>
                  <span
                    style={{
                      marginLeft: "auto",
                      color: "#64748b",
                      fontSize: 11,
                    }}
                  >
                    {entry.latency_ms}ms
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <div className="empty-state">
              <Activity />
              <p>Waiting for events...</p>
            </div>
          )}
        </div>
      </div>

      {/* Pipeline Visualization */}
      <div className="pipeline-viz">
        <h3>🔄 Detection Pipeline</h3>
        <div className="pipeline-steps">
          {[
            "Client",
            "Gateway",
            "Parser",
            "Features",
            "Rules",
            "Anomaly",
            "Behavior",
            "Signals",
            "Decision",
            "App",
          ]
            .map((step, i) => (
              <div key={step} className="pipeline-step active">
                <div className="step-box">{step}</div>
              </div>
            ))
            .reduce((acc, el, i) => {
              if (i > 0)
                acc.push(
                  <span
                    key={`arr-${i}`}
                    className="pipeline-arrow"
                  >
                    →
                  </span>
                );
              acc.push(el);
              return acc;
            }, [])}
        </div>
      </div>
    </div>
  );
}
