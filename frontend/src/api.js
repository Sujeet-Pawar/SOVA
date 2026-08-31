const API_BASE = "http://127.0.0.1:8443/api";

// --- Dashboard Data ---

export async function getStats() {
  const res = await fetch(`${API_BASE}/stats`);
  return res.json();
}

export async function getTimeline() {
  const res = await fetch(`${API_BASE}/timeline`);
  return res.json();
}

export async function getScoreHistory() {
  const res = await fetch(`${API_BASE}/score-history`);
  return res.json();
}

export async function getEvents(limit = 50) {
  const res = await fetch(`${API_BASE}/events?limit=${limit}`);
  return res.json();
}

export async function getEventStats() {
  const res = await fetch(`${API_BASE}/events/stats`);
  return res.json();
}

export async function sendTestRequest(data) {
  const res = await fetch(`${API_BASE}/test-request`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
  return res.json();
}

// --- Export Functions ---

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function getTimestamp() {
  const now = new Date();
  return `${now.getFullYear()}${String(now.getMonth() + 1).padStart(2, "0")}${String(now.getDate()).padStart(2, "0")}_${String(now.getHours()).padStart(2, "0")}${String(now.getMinutes()).padStart(2, "0")}${String(now.getSeconds()).padStart(2, "0")}`;
}

export async function exportEventsCSV(limit = 1000) {
  const res = await fetch(`${API_BASE}/export/events/csv?limit=${limit}`);
  const blob = await res.blob();
  downloadBlob(blob, `sova_waf_events_${getTimestamp()}.csv`);
}

export async function exportEventsJSON(limit = 1000) {
  const res = await fetch(`${API_BASE}/export/events/json?limit=${limit}`);
  const blob = await res.blob();
  downloadBlob(blob, `sova_waf_events_${getTimestamp()}.json`);
}

export async function exportReportJSON() {
  const res = await fetch(`${API_BASE}/export/report/json`);
  const blob = await res.blob();
  downloadBlob(blob, `sova_waf_report_${getTimestamp()}.json`);
}

export async function exportReportHTML() {
  const res = await fetch(`${API_BASE}/export/report/html`);
  const blob = await res.blob();
  downloadBlob(blob, `sova_waf_report_${getTimestamp()}.html`);
}

export async function exportStatsJSON() {
  const res = await fetch(`${API_BASE}/export/stats/json`);
  const blob = await res.blob();
  downloadBlob(blob, `sova_waf_stats_${getTimestamp()}.json`);
}

// --- Training Functions ---

export async function getTrainingStatus() {
  const res = await fetch(`${API_BASE}/training/status`);
  return res.json();
}

export async function startTraining(params) {
  const res = await fetch(`${API_BASE}/training/start`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(params),
  });
  return res.json();
}

export async function getTrainingDataInfo() {
  const res = await fetch(`${API_BASE}/training/data-info`);
  return res.json();
}
