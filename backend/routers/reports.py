"""
routers/reports.py — Incident report generation (V4 Day 1).

POST /reports/generate   — build an HTML incident report for a time range
GET  /reports            — list previously generated reports
GET  /reports/{id}       — fetch a stored report as raw HTML (viewable in browser)

Note: this is HTML-only for now. PDF export via WeasyPrint requires system
libraries (libpango, libcairo, libgdk-pixbuf) not yet in the Dockerfile —
adding it is a deliberately separate, isolated step for a later day rather
than bundling a Dockerfile change into the first report-generation pass.
"""

from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from sqlalchemy import select, func, and_
from sqlalchemy.orm import Session
from database import get_db
from models import Log, Alert, Report

router = APIRouter(prefix="/reports", tags=["reports"])

# Maps MITRE technique IDs used by this app's built-in rules, anomaly engine,
# and correlation engine to their primary tactic, for the heatmap table.
# Techniques that legitimately span multiple tactics (e.g. T1078 Valid
# Accounts) are pinned to the single tactic most relevant to how this app
# uses them, for simplicity — noted here rather than silently guessed.
TECHNIQUE_TACTIC_MAP = {
    "T1595": "Reconnaissance",
    "T1110": "Credential Access",
    "T1078": "Defense Evasion",
    "T1046": "Discovery",
    "T1036": "Defense Evasion",
    "T1498": "Impact",
    "T1499": "Impact",
    "T1041": "Exfiltration",
    "T1071": "Command and Control",
}

MITRE_TACTICS = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
]

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

# Rule-name prefixes used by anomaly_engine.py's four alert types, so the
# "Top Anomalies" report section can pick them out of the alerts table
# (there's no dedicated is_anomaly flag on Alert, so we match by name).
ANOMALY_RULE_PREFIXES = (
    "Traffic Volume Spike", "Unusual Hour Login", "New User Agent", "Impossible Travel",
)


class ReportGenerate(BaseModel):
    start_iso: str
    end_iso: str
    title: str = "Incident Report"


def _heatmap_cell_color(count: int) -> str:
    if count == 0:
        return "#ffffff"
    if count <= 2:
        return "#fef3c7"
    if count <= 5:
        return "#fbbf24"
    if count <= 10:
        return "#f97316"
    return "#ef4444"


def _build_mitre_heatmap_html(technique_counts: dict) -> str:
    """technique_counts: {technique_id: count}. Columns = tactics, rows = fired techniques."""
    tactic_techniques = {t: [] for t in MITRE_TACTICS}
    for tech_id, count in technique_counts.items():
        tactic = TECHNIQUE_TACTIC_MAP.get(tech_id, "Discovery")
        tactic_techniques[tactic].append((tech_id, count))

    max_rows = max((len(v) for v in tactic_techniques.values()), default=0)
    max_rows = max(max_rows, 1)

    header_cells = "".join(f"<th>{t}</th>" for t in MITRE_TACTICS)
    body_rows = ""
    for row_i in range(max_rows):
        cells = ""
        for tactic in MITRE_TACTICS:
            items = tactic_techniques[tactic]
            if row_i < len(items):
                tech_id, count = items[row_i]
                color = _heatmap_cell_color(count)
                cells += (
                    f'<td style="background:{color};text-align:center;'
                    f'font-family:monospace;font-size:12px;padding:6px;">'
                    f'{tech_id}<br/>({count})</td>'
                )
            else:
                cells += '<td style="padding:6px;"></td>'
        body_rows += f"<tr>{cells}</tr>"

    return (
        '<table style="border-collapse:collapse;width:100%;border:1px solid #ccc;">'
        f'<thead><tr>{header_cells}</tr></thead>'
        f'<tbody>{body_rows}</tbody>'
        '</table>'
    )


def _build_report_html(title, start_iso, end_iso, total_events, total_alerts,
                        top_ips, top_rules, heatmap_html, anomalies, alerts) -> str:
    top_ips_rows = "".join(
        f"<tr><td>{ip}</td><td>{count}</td></tr>" for ip, count in top_ips
    ) or "<tr><td colspan='2'>No data</td></tr>"

    top_rules_rows = "".join(
        f"<tr><td>{name}</td><td>{count}</td></tr>" for name, count in top_rules
    ) or "<tr><td colspan='2'>No data</td></tr>"

    anomaly_rows = "".join(
        f"<tr><td>{a['rule_name']}</td><td>{a['severity']}</td>"
        f"<td>{a['source_ip'] or '—'}</td><td>{a['triggered_at']}</td></tr>"
        for a in anomalies
    ) or "<tr><td colspan='4'>No anomalies in this period</td></tr>"

    alert_rows = "".join(
        f"<tr><td>{a['severity']}</td><td>{a['rule_name']}</td>"
        f"<td>{a['source_ip'] or '—'}</td><td>{a['mitre_technique_id'] or '—'}</td>"
        f"<td>{a['status']}</td><td>{a['triggered_at']}</td></tr>"
        for a in alerts
    ) or "<tr><td colspan='6'>No alerts in this period</td></tr>"

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>{title}</title>
<style>
body {{ font-family: -apple-system, Segoe UI, Arial, sans-serif; background:#f8f9fa; color:#1a1a1a; padding:32px; }}
h1 {{ font-size: 22px; }} h2 {{ font-size: 16px; margin-top:32px; border-bottom:2px solid #333; padding-bottom:4px; }}
table {{ border-collapse:collapse; width:100%; margin-top:8px; }}
th, td {{ border:1px solid #ddd; padding:6px 10px; text-align:left; font-size:13px; }}
th {{ background:#eee; }}
.summary-grid {{ display:flex; gap:24px; margin-top:12px; }}
.summary-box {{ background:#fff; border:1px solid #ddd; border-radius:8px; padding:16px 24px; }}
.summary-box .num {{ font-size:28px; font-weight:700; }}
.summary-box .label {{ font-size:12px; color:#666; }}
</style></head>
<body>
<h1>{title}</h1>
<p>Period: {start_iso} &rarr; {end_iso}</p>

<h2>Executive Summary</h2>
<div class="summary-grid">
  <div class="summary-box"><div class="num">{total_events}</div><div class="label">Total Events</div></div>
  <div class="summary-box"><div class="num">{total_alerts}</div><div class="label">Total Alerts</div></div>
</div>
<h3>Top 5 Source IPs</h3>
<table><thead><tr><th>Source IP</th><th>Event Count</th></tr></thead><tbody>{top_ips_rows}</tbody></table>
<h3>Top 5 Alert Rules Fired</h3>
<table><thead><tr><th>Rule Name</th><th>Fire Count</th></tr></thead><tbody>{top_rules_rows}</tbody></table>

<h2>MITRE ATT&amp;CK Technique Heatmap</h2>
{heatmap_html}

<h2>Top Anomalies</h2>
<table><thead><tr><th>Rule Name</th><th>Severity</th><th>Source IP</th><th>Triggered At</th></tr></thead>
<tbody>{anomaly_rows}</tbody></table>

<h2>All Alerts (sorted by severity)</h2>
<table><thead><tr><th>Severity</th><th>Rule Name</th><th>Source IP</th><th>MITRE</th><th>Status</th><th>Triggered At</th></tr></thead>
<tbody>{alert_rows}</tbody></table>

</body></html>"""


@router.post("/generate")
async def generate_report(body: ReportGenerate, db: Session = Depends(get_db)):
    try:
        start_dt = datetime.fromisoformat(body.start_iso.replace("Z", "+00:00"))
        end_dt = datetime.fromisoformat(body.end_iso.replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(status_code=400, detail="start_iso/end_iso must be valid ISO 8601 timestamps")

    total_events = db.execute(
        select(func.count()).select_from(Log).where(
            and_(Log.timestamp >= start_dt, Log.timestamp <= end_dt)
        )
    ).scalar_one()

    total_alerts = db.execute(
        select(func.count()).select_from(Alert).where(
            and_(Alert.triggered_at >= start_dt, Alert.triggered_at <= end_dt)
        )
    ).scalar_one()

    top_ips_rows = db.execute(
        select(Log.source_ip, func.count().label("cnt"))
        .where(and_(Log.timestamp >= start_dt, Log.timestamp <= end_dt, Log.source_ip.isnot(None)))
        .group_by(Log.source_ip).order_by(func.count().desc()).limit(5)
    ).all()
    top_ips = [(str(ip), cnt) for ip, cnt in top_ips_rows]

    top_rules_rows = db.execute(
        select(Alert.rule_name, func.count().label("cnt"))
        .where(and_(Alert.triggered_at >= start_dt, Alert.triggered_at <= end_dt))
        .group_by(Alert.rule_name).order_by(func.count().desc()).limit(5)
    ).all()
    top_rules = [(name, cnt) for name, cnt in top_rules_rows]

    technique_rows = db.execute(
        select(Alert.mitre_technique_id, func.count().label("cnt"))
        .where(and_(
            Alert.triggered_at >= start_dt, Alert.triggered_at <= end_dt,
            Alert.mitre_technique_id.isnot(None),
        ))
        .group_by(Alert.mitre_technique_id)
    ).all()
    technique_counts = {tech_id: cnt for tech_id, cnt in technique_rows}
    heatmap_html = _build_mitre_heatmap_html(technique_counts)

    all_alerts_rows = db.execute(
        select(Alert).where(and_(Alert.triggered_at >= start_dt, Alert.triggered_at <= end_dt))
    ).scalars().all()
    all_alerts_dicts = [a.to_dict() for a in all_alerts_rows]
    all_alerts_dicts.sort(key=lambda a: SEVERITY_ORDER.get(a["severity"], 9))

    anomalies = [
        a for a in all_alerts_dicts
        if any(a["rule_name"].startswith(p) for p in ANOMALY_RULE_PREFIXES)
    ]

    html = _build_report_html(
        title=body.title, start_iso=body.start_iso, end_iso=body.end_iso,
        total_events=total_events, total_alerts=total_alerts,
        top_ips=top_ips, top_rules=top_rules,
        heatmap_html=heatmap_html, anomalies=anomalies, alerts=all_alerts_dicts,
    )

    report = Report(title=body.title, start_iso=start_dt, end_iso=end_dt, html_content=html)
    db.add(report)
    db.commit()
    db.refresh(report)

    return {**report.to_dict(), "html": html}


@router.get("")
async def list_reports(db: Session = Depends(get_db)):
    reports = db.query(Report).order_by(Report.created_at.desc()).all()
    return {"reports": [r.to_dict() for r in reports]}


@router.get("/{report_id}", response_class=HTMLResponse)
async def get_report(report_id: int, db: Session = Depends(get_db)):
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return HTMLResponse(content=report.html_content)