import { useState } from "react";
import {
  LayoutDashboard,
  FlaskConical,
  ShieldAlert,
  Activity,
  Zap,
  Brain,
} from "lucide-react";
import { useWebSocket } from "./hooks/useWebSocket";
import Dashboard from "./pages/Dashboard";
import RequestTester from "./pages/RequestTester";
import SecurityEvents from "./pages/SecurityEvents";
import ModelTraining from "./pages/ModelTraining";
import "./index.css";

const NAV_ITEMS = [
  { id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
  { id: "tester", label: "Request Tester", icon: FlaskConical },
  { id: "events", label: "Security Events", icon: ShieldAlert },
  { id: "training", label: "Model Training", icon: Brain },
];

export default function App() {
  const [page, setPage] = useState("dashboard");
  const { events, stats, connected, clearEvents } = useWebSocket();

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="sidebar-logo">
          <h1>🛡️ SOVA-WAF</h1>
          <div className="subtitle">Anomaly Detection Dashboard</div>
        </div>

        {/* Connection status */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 8,
            padding: "8px 20px",
            fontSize: 12,
            color: connected ? "#10b981" : "#ef4444",
            borderBottom: "1px solid var(--border)",
            marginBottom: 16,
          }}
        >
          <div
            style={{
              width: 8,
              height: 8,
              borderRadius: "50%",
              background: connected ? "#10b981" : "#ef4444",
              boxShadow: connected
                ? "0 0 6px rgba(16,185,129,0.5)"
                : "0 0 6px rgba(239,68,68,0.5)",
            }}
          />
          {connected ? "Live — Streaming" : "Disconnected"}
        </div>

        {NAV_ITEMS.map((item) => (
          <div
            key={item.id}
            className={`nav-item ${page === item.id ? "active" : ""}`}
            onClick={() => setPage(item.id)}
          >
            <item.icon />
            {item.label}
          </div>
        ))}
        <div style={{ flex: 1 }} />
        <div className="nav-item" style={{ opacity: 0.5, cursor: "default" }}>
          <Activity />
          <span>v0.1</span>
        </div>
      </aside>

      <main className="main">
        {page === "dashboard" && (
          <Dashboard events={events} stats={stats} />
        )}
        {page === "tester" && <RequestTester />}
        {page === "events" && (
          <SecurityEvents events={events} clearEvents={clearEvents} />
        )}
        {page === "training" && <ModelTraining />}
      </main>
    </div>
  );
}
