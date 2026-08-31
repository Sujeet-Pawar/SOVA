"""Export Routes - endpoints for downloading detection reports and event logs."""

import sys
import csv
import json
import io
import sqlite3
from pathlib import Path
from datetime import datetime

from fastapi import APIRouter, Query
from fastapi.responses import StreamingResponse, HTMLResponse

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import yaml


def load_config() -> dict:
    config_path = PROJECT_ROOT / "config" / "config.yaml"
    if config_path.exists():
        with open(config_path) as f:
            return yaml.safe_load(f)
    return {}


router = APIRouter(prefix="/api/export", tags=["export"])
config = load_config()
DB_PATH = config.get("logging", {}).get("database", "data/sova_waf.db")


def _get_events(limit: int = 1000) -> list[dict]:
    """Fetch events from SQLite."""
    events = []
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM security_events ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        events = [dict(row) for row in cursor.fetchall()]
        conn.close()
    except Exception:
        pass
    return events


def _get_stats() -> dict:
    """Fetch aggregate stats from SQLite."""
    stats = {
        "total_events": 0,
        "by_threat_type": {},
        "by_action": {},
        "avg_scores": {"rule": 0, "anomaly": 0, "behavior": 0},
        "detection_rate": 0,
        "top_endpoints": {},
    }
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM security_events")
        stats["total_events"] = cursor.fetchone()[0]

        cursor.execute("SELECT threat_type, COUNT(*) FROM security_events GROUP BY threat_type")
        stats["by_threat_type"] = {row[0]: row[1] for row in cursor.fetchall()}

        cursor.execute("SELECT action, COUNT(*) FROM security_events GROUP BY action")
        stats["by_action"] = {row[0]: row[1] for row in cursor.fetchall()}

        cursor.execute("SELECT endpoint, COUNT(*) FROM security_events GROUP BY endpoint ORDER BY COUNT(*) DESC LIMIT 10")
        stats["top_endpoints"] = {row[0]: row[1] for row in cursor.fetchall()}

        cursor.execute("SELECT AVG(rule_score), AVG(anomaly_score), AVG(behavior_score) FROM security_events")
        row = cursor.fetchone()
        if row and row[0] is not None:
            stats["avg_scores"] = {
                "rule": round(row[0], 4),
                "anomaly": round(row[1], 4),
                "behavior": round(row[2], 4),
            }

        total = stats["total_events"]
        blocked = stats["by_action"].get("BLOCK", 0) + stats["by_action"].get("FLAG", 0)
        stats["detection_rate"] = round(blocked / max(1, total) * 100, 2)

        conn.close()
    except Exception:
        pass
    return stats


@router.get("/events/csv")
async def export_events_csv(limit: int = Query(default=1000, le=10000)):
    """Export security events as CSV."""
    events = _get_events(limit)

    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow([
        "ID", "Timestamp", "Request ID", "Source", "Endpoint", "Method",
        "Threat Type", "Rule Score", "Anomaly Score", "Behavior Score",
        "Action", "Reason",
    ])

    # Rows
    for e in events:
        writer.writerow([
            e.get("id", ""),
            e.get("timestamp", ""),
            e.get("request_id", ""),
            e.get("source_id", ""),
            e.get("endpoint", ""),
            e.get("method", ""),
            e.get("threat_type", ""),
            e.get("rule_score", ""),
            e.get("anomaly_score", ""),
            e.get("behavior_score", ""),
            e.get("action", ""),
            e.get("reason", ""),
        ])

    output.seek(0)
    filename = f"sova_waf_events_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/events/json")
async def export_events_json(limit: int = Query(default=1000, le=10000)):
    """Export security events as JSON."""
    events = _get_events(limit)
    filename = f"sova_waf_events_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"

    content = json.dumps({"events": events, "exported_at": datetime.utcnow().isoformat()}, indent=2)

    return StreamingResponse(
        iter([content]),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/report/json")
async def export_report_json():
    """Export full detection report as JSON."""
    stats = _get_stats()
    events = _get_events(100)

    report = {
        "report_type": "SOVA-WAF Detection Report",
        "generated_at": datetime.utcnow().isoformat(),
        "summary": stats,
        "recent_events": events,
    }

    filename = f"sova_waf_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    content = json.dumps(report, indent=2)

    return StreamingResponse(
        iter([content]),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/report/html")
async def export_report_html():
    """Export full detection report as a styled HTML page."""
    stats = _get_stats()
    events = _get_events(50)

    threat_rows = ""
    for t, c in stats["by_threat_type"].items():
        threat_rows += f"<tr><td>{t.replace('_', ' ')}</td><td>{c}</td></tr>\n"

    endpoint_rows = ""
    for ep, c in stats["top_endpoints"].items():
        endpoint_rows += f"<tr><td>{ep}</td><td>{c}</td></tr>\n"

    event_rows = ""
    for e in events:
        action_color = {"BLOCK": "#ef4444", "FLAG": "#f59e0b", "ALLOW": "#10b981"}.get(e.get("action", ""), "#64748b")
        event_rows += f"""<tr>
            <td>{e.get('timestamp', '-')[:19]}</td>
            <td>{e.get('request_id', '-')}</td>
            <td>{e.get('source_id', '-')}</td>
            <td>{e.get('endpoint', '-')}</td>
            <td>{e.get('threat_type', 'NONE').replace('_', ' ')}</td>
            <td>{e.get('rule_score', 0):.2f}</td>
            <td>{e.get('anomaly_score', 0):.2f}</td>
            <td>{e.get('behavior_score', 0):.2f}</td>
            <td style="color:{action_color};font-weight:700">{e.get('action', '-')}</td>
        </tr>\n"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SOVA-WAF Detection Report</title>
<style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0a0e17; color: #e2e8f0; padding: 40px; }}
    h1 {{ color: #06b6d4; font-size: 28px; margin-bottom: 4px; }}
    .subtitle {{ color: #64748b; font-size: 13px; margin-bottom: 32px; }}
    .grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 32px; }}
    .card {{ background: #1a2236; border: 1px solid #2a3550; border-radius: 12px; padding: 20px; }}
    .card .label {{ font-size: 11px; color: #64748b; text-transform: uppercase; letter-spacing: 0.5px; }}
    .card .value {{ font-size: 28px; font-weight: 700; margin-top: 4px; }}
    .card .value.green {{ color: #10b981; }}
    .card .value.red {{ color: #ef4444; }}
    .card .value.yellow {{ color: #f59e0b; }}
    .card .value.blue {{ color: #3b82f6; }}
    table {{ width: 100%; border-collapse: collapse; margin-bottom: 24px; }}
    th {{ text-align: left; padding: 10px 12px; font-size: 11px; color: #64748b; text-transform: uppercase; border-bottom: 1px solid #2a3550; }}
    td {{ padding: 10px 12px; font-size: 13px; border-bottom: 1px solid #1a2236; color: #94a3b8; }}
    tr:hover td {{ background: #111827; }}
    h2 {{ font-size: 18px; margin-bottom: 16px; color: #e2e8f0; }}
    .footer {{ margin-top: 40px; padding-top: 16px; border-top: 1px solid #2a3550; color: #64748b; font-size: 12px; }}
</style>
</head>
<body>
<h1>🛡️ SOVA-WAF Detection Report</h1>
<div class="subtitle">Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</div>

<div class="grid">
    <div class="card"><div class="label">Total Events</div><div class="value blue">{stats['total_events']}</div></div>
    <div class="card"><div class="label">Detection Rate</div><div class="value red">{stats['detection_rate']}%</div></div>
    <div class="card"><div class="label">Avg Rule Score</div><div class="value yellow">{stats['avg_scores']['rule']:.3f}</div></div>
    <div class="card"><div class="label">Avg Anomaly Score</div><div class="value yellow">{stats['avg_scores']['anomaly']:.3f}</div></div>
</div>

<h2>Threat Types</h2>
<table>
<tr><th>Threat Type</th><th>Count</th></tr>
{threat_rows if threat_rows else '<tr><td colspan="2">No threats detected</td></tr>'}
</table>

<h2>Top Targeted Endpoints</h2>
<table>
<tr><th>Endpoint</th><th>Hits</th></tr>
{endpoint_rows if endpoint_rows else '<tr><td colspan="2">No endpoint data</td></tr>'}
</table>

<h2>Recent Security Events (last {len(events)})</h2>
<table>
<tr><th>Time</th><th>Request ID</th><th>Source</th><th>Endpoint</th><th>Threat</th><th>Rule</th><th>Anomaly</th><th>Behavior</th><th>Action</th></tr>
{event_rows if event_rows else '<tr><td colspan="9">No events recorded</td></tr>'}
</table>

<div class="footer">
    SOVA-WAF v0.1 — Anomaly Detection Web Application Firewall<br>
    Report generated by SOVA-WAF export system
</div>
</body>
</html>"""

    filename = f"sova_waf_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.html"

    return StreamingResponse(
        iter([html]),
        media_type="text/html",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/stats/json")
async def export_stats_json():
    """Export current statistics as JSON."""
    stats = _get_stats()
    filename = f"sova_waf_stats_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"

    content = json.dumps(stats, indent=2)

    return StreamingResponse(
        iter([content]),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
