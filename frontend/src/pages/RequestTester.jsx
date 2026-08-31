import { useState } from "react";
import { Play, Zap, Download } from "lucide-react";
import { sendTestRequest } from "../api";

const QUICK_ATTACKS = [
  {
    label: "Normal GET",
    class: "normal",
    data: { method: "GET", path: "/", query_string: "" },
  },
  {
    label: "Normal Search",
    class: "normal",
    data: { method: "GET", path: "/search", query_string: "q=laptop" },
  },
  {
    label: "SQLi: OR bypass",
    class: "sqli",
    data: {
      method: "GET",
      path: "/search",
      query_string: "q=' OR '1'='1",
    },
  },
  {
    label: "SQLi: UNION SELECT",
    class: "sqli",
    data: {
      method: "GET",
      path: "/search",
      query_string: "q=' UNION SELECT NULL,NULL,NULL--",
    },
  },
  {
    label: "SQLi: Comment",
    class: "sqli",
    data: {
      method: "GET",
      path: "/search",
      query_string: "q=admin'--",
    },
  },
  {
    label: "XSS: Script tag",
    class: "xss",
    data: {
      method: "GET",
      path: "/search",
      query_string: "q=<script>alert('XSS')</script>",
    },
  },
  {
    label: "XSS: onerror",
    class: "xss",
    data: {
      method: "GET",
      path: "/search",
      query_string: "q=<img src=x onerror=alert(1)>",
    },
  },
  {
    label: "XSS: javascript:",
    class: "xss",
    data: {
      method: "GET",
      path: "/redirect",
      query_string: "url=javascript:alert(1)",
    },
  },
  {
    label: "Traversal: /etc/passwd",
    class: "traversal",
    data: {
      method: "GET",
      path: "/download",
      query_string: "file=../../../etc/passwd",
    },
  },
  {
    label: "Traversal: encoded",
    class: "traversal",
    data: {
      method: "GET",
      path: "/download",
      query_string: "file=..%2f..%2f..%2fetc/passwd",
    },
  },
  {
    label: "Cmd: pipe injection",
    class: "cmd",
    data: {
      method: "GET",
      path: "/search",
      query_string: "q=test; ls -la",
    },
  },
  {
    label: "Cmd: backtick",
    class: "cmd",
    data: {
      method: "GET",
      path: "/search",
      query_string: "q=`whoami`",
    },
  },
];

function ScoreBar({ label, value, color }) {
  const pct = Math.min(100, value * 100);
  const barColor =
    pct > 60 ? "red" : pct > 30 ? "yellow" : "green";
  return (
    <div className="score-bar-group">
      <div className="score-bar-label">
        <span>{label}</span>
        <span style={{ color: `var(--accent-${color || barColor})` }}>
          {value.toFixed(3)}
        </span>
      </div>
      <div className="score-bar-track">
        <div
          className={`score-bar-fill ${barColor}`}
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  );
}

export default function RequestTester() {
  const [form, setForm] = useState({
    method: "GET",
    path: "/search",
    query_string: "q=laptop",
    body: "",
    source_id: "FRONTEND-TEST",
  });
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async () => {
    setLoading(true);
    try {
      const data = await sendTestRequest(form);
      setResult(data);
    } catch (e) {
      console.error(e);
    }
    setLoading(false);
  };

  const handleQuickAttack = (attack) => {
    setForm({ ...form, ...attack.data });
    setResult(null);
  };

  return (
    <div>
      <div className="page-header">
        <h2>Request Tester</h2>
        <p>
          Send requests through the full SOVA-WAF detection pipeline and see
          results in real time
        </p>
      </div>

      {/* Quick Attack Buttons */}
      <div style={{ marginBottom: 16 }}>
        <div
          style={{
            fontSize: 12,
            color: "var(--text-muted)",
            marginBottom: 8,
            textTransform: "uppercase",
            letterSpacing: "0.5px",
          }}
        >
          Quick Test Payloads
        </div>
        <div className="quick-attacks">
          {QUICK_ATTACKS.map((attack) => (
            <button
              key={attack.label}
              className={`attack-btn ${attack.class}`}
              onClick={() => handleQuickAttack(attack)}
            >
              {attack.label}
            </button>
          ))}
        </div>
      </div>

      <div className="tester-container">
        {/* Form */}
        <div className="tester-form">
          <h3>Request Configuration</h3>
          <div className="form-row">
            <div className="form-group" style={{ flex: "0 0 120px" }}>
              <label>Method</label>
              <select
                value={form.method}
                onChange={(e) =>
                  setForm({ ...form, method: e.target.value })
                }
              >
                <option>GET</option>
                <option>POST</option>
                <option>PUT</option>
                <option>DELETE</option>
              </select>
            </div>
            <div className="form-group">
              <label>Path</label>
              <input
                value={form.path}
                onChange={(e) =>
                  setForm({ ...form, path: e.target.value })
                }
                placeholder="/search"
              />
            </div>
          </div>
          <div className="form-group">
            <label>Query String</label>
            <input
              value={form.query_string}
              onChange={(e) =>
                setForm({ ...form, query_string: e.target.value })
              }
              placeholder="q=laptop&page=1"
            />
          </div>
          <div className="form-group">
            <label>Body (optional)</label>
            <textarea
              rows={3}
              value={form.body}
              onChange={(e) => setForm({ ...form, body: e.target.value })}
              placeholder="username=admin&password=test"
            />
          </div>
          <div className="form-group">
            <label>Source ID</label>
            <input
              value={form.source_id}
              onChange={(e) =>
                setForm({ ...form, source_id: e.target.value })
              }
              placeholder="CLIENT-001"
            />
          </div>
          <button
            className="btn btn-primary"
            onClick={handleSubmit}
            disabled={loading}
            style={{ marginTop: 12, width: "100%" }}
          >
            <span style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 8 }}>
              {loading ? "Analyzing..." : "Send Request"}
              {!loading && <Play size={14} />}
            </span>
          </button>
        </div>

        {/* Results */}
        <div className="result-panel">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
            <h3 style={{ margin: 0 }}>Detection Results</h3>
            {result && (
              <button
                className="btn btn-outline"
                onClick={() => {
                  const blob = new Blob([JSON.stringify(result, null, 2)], { type: "application/json" });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement("a");
                  a.href = url;
                  a.download = `sova_test_result_${Date.now()}.json`;
                  a.click();
                  URL.revokeObjectURL(url);
                }}
                title="Export this result"
              >
                <span style={{ display: "flex", alignItems: "center", gap: 4 }}>
                  <Download size={12} />
                  Export
                </span>
              </button>
            )}
          </div>
          {!result ? (
            <div className="empty-state">
              <Zap />
              <p>Send a request to see detection results</p>
            </div>
          ) : (
            <div>
              {/* Action Badge */}
              <div style={{ marginBottom: 16 }}>
                <span className={`action-badge ${result.signals.action}`}>
                  {result.signals.action}
                </span>
                <span
                  style={{
                    marginLeft: 12,
                    fontSize: 12,
                    color: "var(--text-muted)",
                  }}
                >
                  {result.latency_ms}ms
                </span>
              </div>

              {/* Score Bars */}
              <ScoreBar
                label="Rule Score"
                value={result.signals.known_threat_score}
                color="blue"
              />
              <ScoreBar
                label="Anomaly Score"
                value={result.signals.anomaly_score}
                color="yellow"
              />
              <ScoreBar
                label="Behavior Score"
                value={result.signals.behavior_score}
                color="purple"
              />

              {/* Anomaly Classification */}
              {result.detection.anomaly_result && (
                <div
                  style={{
                    marginTop: 16,
                    padding: 10,
                    background: "var(--bg-primary)",
                    borderRadius: 8,
                    border: "1px solid var(--border)",
                  }}
                >
                  <div
                    style={{
                      fontSize: 12,
                      color: "var(--text-muted)",
                      marginBottom: 4,
                    }}
                  >
                    Anomaly Classification
                  </div>
                  <div
                    style={{
                      fontSize: 14,
                      fontWeight: 600,
                      color:
                        result.detection.anomaly_result.classification ===
                        "ANOMALOUS"
                          ? "var(--accent-yellow)"
                          : "var(--accent-green)",
                    }}
                  >
                    {result.detection.anomaly_result.classification}
                  </div>
                  <div
                    style={{
                      fontSize: 11,
                      color: "var(--text-muted)",
                      marginTop: 4,
                    }}
                  >
                    {result.detection.anomaly_result.reason}
                  </div>
                </div>
              )}

              {/* Explanations */}
              {result.signals.explanations.length > 0 && (
                <div className="explanations" style={{ marginTop: 12 }}>
                  <div
                    style={{
                      fontSize: 12,
                      color: "var(--text-muted)",
                      marginBottom: 6,
                    }}
                  >
                    Explanations
                  </div>
                  {result.signals.explanations.map((exp, i) => (
                    <div key={i} className="explanation-item">
                      {exp}
                    </div>
                  ))}
                </div>
              )}

              {/* Rule Details */}
              {result.detection.rule_results.length > 0 && (
                <div style={{ marginTop: 16 }}>
                  <div
                    style={{
                      fontSize: 12,
                      color: "var(--text-muted)",
                      marginBottom: 8,
                    }}
                  >
                    Rule Detectors
                  </div>
                  {result.detection.rule_results.map((r, i) => (
                    <div key={i} className="detection-detail">
                      <div className="header">
                        <span className="detector-name">{r.detector}</span>
                        <span className={`threat-tag ${r.threat_type}`}>
                          {r.threat_type.replace("_", " ")}
                        </span>
                      </div>
                      <div className="reason">{r.reason}</div>
                      {r.evidence.length > 0 && (
                        <div className="evidence">
                          {r.evidence.map((e, j) => (
                            <div key={j} className="evidence-item">
                              → {e}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
