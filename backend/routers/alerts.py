import uuid
import csv
import io
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel
from sqlalchemy import select, and_, func
from sqlalchemy.ext.asyncio import AsyncSession
from database import get_db
from models import Alert, Log

router = APIRouter(prefix="/alerts", tags=["alerts"])

VALID_TRANSITIONS = {
    "NEW": ["ACKNOWLEDGED", "INVESTIGATING", "RESOLVED"],
    "ACKNOWLEDGED": ["INVESTIGATING", "RESOLVED"],
    "INVESTIGATING": ["RESOLVED"],
    "RESOLVED": [],
}

class StatusUpdate(BaseModel):
    status: str
    notes: str | None = None

@router.get("")
async def list_alerts(
    status: str | None = Query(None),
    severity: str | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    conditions = []
    if status:
        conditions.append(Alert.status == status.upper())
    if severity:
        conditions.append(Alert.severity == severity.upper())
    where = and_(*conditions) if conditions else True
    total = (db.execute(select(func.count()).select_from(Alert).where(where))).scalar_one()
    offset = (page - 1) * page_size
    result = db.execute(select(Alert).where(where).order_by(Alert.triggered_at.desc()).offset(offset).limit(page_size))
    alerts = result.scalars().all()
    return {"total": total, "page": page, "page_size": page_size, "alerts": [a.to_dict() for a in alerts]}


@router.get("/export")
async def export_alerts(
    format: str = Query("csv", pattern="^(csv|json)$"),
    start: str | None = Query(None, description="ISO 8601 start of triggered_at range"),
    end: str | None = Query(None, description="ISO 8601 end of triggered_at range"),
    severity: str | None = Query(None),
    status: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """
    Exports alerts as CSV or JSON, respecting date range / severity /
    status filters.

    Column mapping note: this schema doesn't have group_value,
    matched_count, first_seen, or last_seen fields (an earlier design
    than what's actually implemented). Mapped to the closest real
    equivalents: group_value -> source_ip, first_seen/last_seen -> both
    map to triggered_at (no separate first/last tracking exists),
    matched_count is omitted (not tracked).
    """
    conditions = []
    if start:
        try:
            start_dt = datetime.fromisoformat(start.replace("Z", "+00:00"))
            conditions.append(Alert.triggered_at >= start_dt)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid start date, must be ISO 8601")
    if end:
        try:
            end_dt = datetime.fromisoformat(end.replace("Z", "+00:00"))
            conditions.append(Alert.triggered_at <= end_dt)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid end date, must be ISO 8601")
    if severity:
        conditions.append(Alert.severity == severity.upper())
    if status:
        conditions.append(Alert.status == status.upper())

    where = and_(*conditions) if conditions else True
    result = db.execute(select(Alert).where(where).order_by(Alert.triggered_at.desc()))
    alerts = result.scalars().all()

    rows = [
        {
            "id": a.id,
            "rule_name": a.rule_name,
            "severity": a.severity.value if a.severity else None,
            "status": a.status.value if a.status else None,
            "group_value": str(a.source_ip) if a.source_ip else None,
            "matched_count": None,
            "first_seen": a.triggered_at.isoformat() if a.triggered_at else None,
            "last_seen": a.triggered_at.isoformat() if a.triggered_at else None,
            "mitre_technique_id": a.mitre_technique_id,
        }
        for a in alerts
    ]

    if format == "json":
        return JSONResponse(content=rows)

    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=["id", "rule_name", "severity", "status", "group_value",
                    "matched_count", "first_seen", "last_seen", "mitre_technique_id"],
    )
    writer.writeheader()
    writer.writerows(rows)

    filename = f"alerts-export-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.csv"
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )

@router.get("/{alert_id}")
async def get_alert(alert_id: str, db: AsyncSession = Depends(get_db)):
    result = db.execute(select(Alert).where(Alert.id == int(alert_id)))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert.to_dict()
@router.get("/{alert_id}/timeline")
async def get_alert_timeline(alert_id: str, db: AsyncSession = Depends(get_db)):
    """
    For a correlation alert, returns the two stage events (log_a, log_b)
    that triggered it, in order, for rendering as a swimlane timeline.
    Returns 404 if the alert isn't a correlation alert or the linked
    logs were deleted (e.g. by log retention).
    """
    result = db.execute(select(Alert).where(Alert.id == int(alert_id)))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    if not alert.correlation_log_a_id or not alert.correlation_log_b_id:
        raise HTTPException(status_code=404, detail="This alert has no timeline data (not a correlation alert)")

    log_a = db.execute(select(Log).where(Log.id == alert.correlation_log_a_id)).scalar_one_or_none()
    log_b = db.execute(select(Log).where(Log.id == alert.correlation_log_b_id)).scalar_one_or_none()

    if not log_a or not log_b:
        raise HTTPException(status_code=404, detail="Linked log events no longer exist (may have been retention-deleted)")

    return {
        "alert": alert.to_dict(),
        "stages": [
            {"stage": "A", "log": log_a.to_dict()},
            {"stage": "B", "log": log_b.to_dict()},
        ],
    }


@router.patch("/{alert_id}/status")
async def update_alert_status(alert_id: str, body: StatusUpdate, db: AsyncSession = Depends(get_db)):
    result = db.execute(select(Alert).where(Alert.id == int(alert_id)))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    new_status = body.status.upper()
    allowed = VALID_TRANSITIONS.get(alert.status, [])
    if new_status not in allowed:
        raise HTTPException(status_code=400, detail=f"Cannot transition from {alert.status} to {new_status}. Allowed: {allowed}")
    alert.status = new_status
    now = datetime.now(timezone.utc)
    if new_status == "ACKNOWLEDGED":
        alert.acknowledged_at = now
    if new_status == "RESOLVED":
        alert.resolved_at = now
    if body.notes:
        existing = alert.notes or ""
        timestamp = now.strftime("%Y-%m-%d %H:%M:%S")
        alert.notes = f"{existing}\n[{timestamp}] {body.notes}".strip()
    db.commit()
    return alert.to_dict()


