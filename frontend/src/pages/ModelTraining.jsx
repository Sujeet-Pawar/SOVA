import { useState, useEffect, useCallback } from "react";
import {
  Brain,
  Play,
  RefreshCw,
  CheckCircle,
  XCircle,
  Database,
  Cpu,
  BarChart3,
  Settings,
} from "lucide-react";
import { getTrainingStatus, startTraining, getTrainingDataInfo } from "../api";

export default function ModelTraining() {
  const [status, setStatus] = useState(null);
  const [dataInfo, setDataInfo] = useState(null);
  const [loading, setLoading] = useState(false);
  const [params, setParams] = useState({
    contamination: 0.1,
    n_estimators: 100,
    random_state: 42,
    train_split: "train",
  });

  const loadData = useCallback(async () => {
    try {
      const [s, d] = await Promise.all([getTrainingStatus(), getTrainingDataInfo()]);
      setStatus(s);
      setDataInfo(d);
    } catch (e) {
      console.error("Failed to load training data:", e);
    }
  }, []);

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 2000);
    return () => clearInterval(interval);
  }, [loadData]);

  const handleStartTraining = async () => {
    setLoading(true);
    try {
      await startTraining(params);
    } catch (e) {
      console.error("Failed to start training:", e);
    }
    setLoading(false);
  };

  const isRunning = status?.status === "running" || status?.status === "queued";

  return (
    <div>
      <div className="page-header">
        <h2>Model Training</h2>
        <p>Retrain the Isolation Forest anomaly detection model</p>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
        {/* Left Column: Config + Train */}
        <div>
          {/* Training Status */}
          <div
            className="chart-card"
            style={{ marginBottom: 16 }}
          >
            <h3 style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <Cpu size={16} />
              Training Status
            </h3>
            <div
              style={{
                padding: 16,
                background: "var(--bg-primary)",
                borderRadius: 8,
                border: "1px solid var(--border)",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 12 }}>
                <span
                  style={{
                    width: 10,
                    height: 10,
                    borderRadius: "50%",
                    background:
                      status?.status === "completed"
                        ? "var(--accent-green)"
                        : status?.status === "running"
                        ? "var(--accent-yellow)"
                        : status?.status === "error"
                        ? "var(--accent-red)"
                        : "var(--text-muted)",
                  }}
                />
                <span style={{ fontSize: 14, fontWeight: 600, textTransform: "capitalize" }}>
                  {status?.status || "idle"}
                </span>
              </div>

              {/* Progress Bar */}
              <div style={{ marginBottom: 12 }}>
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    fontSize: 12,
                    marginBottom: 4,
                  }}
                >
                  <span style={{ color: "var(--text-muted)" }}>Progress</span>
                  <span style={{ fontFamily: "monospace" }}>
                    {status?.progress || 0}%
                  </span>
                </div>
                <div
                  style={{
                    height: 8,
                    background: "var(--bg-card)",
                    borderRadius: 4,
                    overflow: "hidden",
                  }}
                >
                  <div
                    style={{
                      height: "100%",
                      width: `${status?.progress || 0}%`,
                      background:
                        status?.status === "error"
                          ? "var(--accent-red)"
                          : status?.status === "completed"
                          ? "var(--accent-green)"
                          : "var(--accent-blue)",
                      borderRadius: 4,
                      transition: "width 0.3s",
                    }}
                  />
                </div>
              </div>

              <div style={{ fontSize: 12, color: "var(--text-muted)" }}>
                {status?.message || "No training job running"}
              </div>

              {status?.completed_at && (
                <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 6 }}>
                  Completed: {new Date(status.completed_at).toLocaleString()}
                </div>
              )}
            </div>
          </div>

          {/* Training Parameters */}
          <div className="chart-card" style={{ marginBottom: 16 }}>
            <h3 style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <Settings size={16} />
              Training Parameters
            </h3>

            <div className="form-group" style={{ marginBottom: 12 }}>
              <label>Contamination (expected anomaly ratio)</label>
              <input
                type="number"
                min="0.01"
                max="0.5"
                step="0.01"
                value={params.contamination}
                onChange={(e) =>
                  setParams({ ...params, contamination: parseFloat(e.target.value) || 0.1 })
                }
                disabled={isRunning}
              />
              <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4 }}>
                Fraction of training data expected to be anomalous (0.01 - 0.5)
              </div>
            </div>

            <div className="form-group" style={{ marginBottom: 12 }}>
              <label>Number of Estimators (trees)</label>
              <input
                type="number"
                min="10"
                max="500"
                step="10"
                value={params.n_estimators}
                onChange={(e) =>
                  setParams({ ...params, n_estimators: parseInt(e.target.value) || 100 })
                }
                disabled={isRunning}
              />
              <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4 }}>
                More trees = better detection but slower training
              </div>
            </div>

            <div className="form-group" style={{ marginBottom: 12 }}>
              <label>Random State (seed)</label>
              <input
                type="number"
                min="0"
                value={params.random_state}
                onChange={(e) =>
                  setParams({ ...params, random_state: parseInt(e.target.value) || 42 })
                }
                disabled={isRunning}
              />
              <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4 }}>
                For reproducible results
              </div>
            </div>

            <div className="form-group" style={{ marginBottom: 16 }}>
              <label>Training Data Split</label>
              <select
                value={params.train_split}
                onChange={(e) => setParams({ ...params, train_split: e.target.value })}
                disabled={isRunning}
              >
                <option value="train">Train (recommended)</option>
                <option value="all">All normalized data</option>
              </select>
            </div>

            <button
              className="btn btn-primary"
              onClick={handleStartTraining}
              disabled={isRunning || loading}
              style={{ width: "100%" }}
            >
              <span style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 8 }}>
                {isRunning ? (
                  <>
                    <RefreshCw size={14} className="spin" />
                    Training in Progress...
                  </>
                ) : (
                  <>
                    <Brain size={14} />
                    Start Training
                  </>
                )}
              </span>
            </button>
          </div>
        </div>

        {/* Right Column: Data Info + Results */}
        <div>
          {/* Data Info */}
          <div className="chart-card" style={{ marginBottom: 16 }}>
            <h3 style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <Database size={16} />
              Training Data
            </h3>

            {dataInfo ? (
              <div>
                {/* Current Model */}
                <div
                  style={{
                    padding: 12,
                    background: "var(--bg-primary)",
                    borderRadius: 8,
                    border: "1px solid var(--border)",
                    marginBottom: 12,
                  }}
                >
                  <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 6 }}>
                    Current Model
                  </div>
                  {dataInfo.model?.exists ? (
                    <div>
                      <div style={{ fontSize: 14, fontWeight: 600, color: "var(--accent-green)" }}>
                        ✓ Model exists
                      </div>
                      <div style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 4 }}>
                        Size: {dataInfo.model.size_kb} KB
                      </div>
                      {dataInfo.model.last_modified && (
                        <div style={{ fontSize: 11, color: "var(--text-muted)" }}>
                          Last trained: {new Date(dataInfo.model.last_modified).toLocaleString()}
                        </div>
                      )}
                    </div>
                  ) : (
                    <div style={{ fontSize: 14, color: "var(--accent-yellow)" }}>
                      ⚠ No model found — train one below
                    </div>
                  )}
                </div>

                {/* Data Splits */}
                {["train", "validation", "test"].map((split) => {
                  const info = dataInfo[split];
                  if (!info) return null;
                  return (
                    <div
                      key={split}
                      style={{
                        padding: 12,
                        background: "var(--bg-primary)",
                        borderRadius: 8,
                        border: "1px solid var(--border)",
                        marginBottom: 8,
                      }}
                    >
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                        <span style={{ fontSize: 13, fontWeight: 600, textTransform: "capitalize" }}>
                          {split} Split
                        </span>
                        <span
                          style={{
                            fontSize: 12,
                            fontFamily: "monospace",
                            color: info.exists ? "var(--accent-green)" : "var(--accent-red)",
                          }}
                        >
                          {info.total} samples
                        </span>
                      </div>
                      {info.labels && Object.keys(info.labels).length > 0 && (
                        <div style={{ display: "flex", gap: 12, marginTop: 6 }}>
                          {Object.entries(info.labels).map(([label, count]) => (
                            <span
                              key={label}
                              style={{
                                fontSize: 11,
                                padding: "2px 6px",
                                borderRadius: 4,
                                background:
                                  label === "NORMAL"
                                    ? "var(--glow-green)"
                                    : "var(--glow-red)",
                                color:
                                  label === "NORMAL"
                                    ? "var(--accent-green)"
                                    : "var(--accent-red)",
                              }}
                            >
                              {label}: {count}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  );
                })}

                {/* Feature Info */}
                {dataInfo.features && (
                  <div
                    style={{
                      padding: 12,
                      background: "var(--bg-primary)",
                      borderRadius: 8,
                      border: "1px solid var(--border)",
                    }}
                  >
                    <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 4 }}>
                      Feature Matrix
                    </div>
                    <div style={{ fontSize: 14, fontWeight: 600 }}>
                      {dataInfo.features.num_samples} samples × {dataInfo.features.num_features} features
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="empty-state">
                <Database />
                <p>Loading data info...</p>
              </div>
            )}
          </div>

          {/* Evaluation Results */}
          {status?.eval_results && (
            <div className="chart-card">
              <h3 style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <BarChart3 size={16} />
                Evaluation Results
              </h3>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                {[
                  { label: "Normal Samples", value: status.eval_results.normal_samples },
                  { label: "Attack Samples", value: status.eval_results.attack_samples },
                  { label: "Precision", value: status.eval_results.precision?.toFixed(3) },
                  { label: "Recall", value: status.eval_results.recall?.toFixed(3) },
                  { label: "F1 Score", value: status.eval_results.f1?.toFixed(3) },
                  { label: "ROC AUC", value: status.eval_results.roc_auc?.toFixed(3) },
                  { label: "Normal FPR", value: status.eval_results.normal_detection_rate?.toFixed(3) },
                  { label: "Attack Detection", value: status.eval_results.attack_detection_rate?.toFixed(3) },
                ].map(({ label, value }) => (
                  <div
                    key={label}
                    style={{
                      padding: 10,
                      background: "var(--bg-primary)",
                      borderRadius: 6,
                      border: "1px solid var(--border)",
                    }}
                  >
                    <div style={{ fontSize: 11, color: "var(--text-muted)" }}>{label}</div>
                    <div
                      style={{
                        fontSize: 16,
                        fontWeight: 700,
                        fontFamily: "monospace",
                        marginTop: 2,
                        color:
                          label.includes("Detection") || label.includes("FPR")
                            ? value > 0.5
                              ? "var(--accent-green)"
                              : "var(--accent-yellow)"
                            : "var(--text-primary)",
                      }}
                    >
                      {value ?? "N/A"}
                    </div>
                  </div>
                ))}
              </div>

              {/* Training Stats */}
              {status.stats && (
                <div
                  style={{
                    marginTop: 12,
                    padding: 12,
                    background: "var(--bg-primary)",
                    borderRadius: 8,
                    border: "1px solid var(--border)",
                  }}
                >
                  <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 6 }}>
                    Training Statistics
                  </div>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
                    {Object.entries(status.stats).map(([key, val]) => (
                      <div key={key} style={{ fontSize: 12 }}>
                        <span style={{ color: "var(--text-muted)" }}>{key}: </span>
                        <span style={{ fontFamily: "monospace" }}>
                          {typeof val === "number" ? val.toFixed(4) : String(val)}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
