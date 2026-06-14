"""
routers/alerts.py — View and manage fired alerts.

GET    /alerts              — list alerts (filterable by status/severity)
GET    /alerts/{id}         — get one alert
PATCH  /alerts/{id}/status  — transition alert status
"""

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models import Alert

router = APIRouter(prefix="/alerts", tags=["alerts"])


# ── Valid status transitions ──────────────────────────────────────────────────
# An alert can only move forward — never backwards
VALID_TRANSITIONS = {
    "NEW":           ["ACKNOWLEDGED", "INVESTIGATING", "RESOLVED"],
    "ACKNOWLEDGED":  ["INVESTIGATING", "RESOLVED"],
    "INVESTIGATING": ["RESOLVED"],
    "RESOLVED":      [],  # terminal state
}


class StatusUpdate(BaseModel):
    status: str
    notes: str | None = None


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("")
async def list_alerts(
    status: str | None = Query(None),
    severity: str | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    """
    List alerts with optional filters.
    Example: GET /alerts?status=NEW&severity=CRITICAL
    """
    conditions = []
    if status:
        conditions.append(Alert.status == status.upper())
    if severity:
        conditions.append(Alert.severity == severity.upper())

    where = and_(*conditions) if conditions else True

    # Count total
    from sqlalchemy import func
    total_result = await db.execute(
        select(func.count()).select_from(Alert).where(where)
    )
    total = total_result.scalar_one()

    # Fetch page
    offset = (page - 1) * page_size
    result = await db.execute(
        select(Alert)
        .where(where)
        .order_by(Alert.last_seen.desc())
        .offset(offset)
        .limit(page_size)
    )
    alerts = result.scalars().all()

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "alerts": [a.to_dict() for a in alerts],
    }


@router.get("/{alert_id}")
async def get_alert(alert_id: str, db: AsyncSession = Depends(get_db)):
    """Get a single alert by ID."""
    result = await db.execute(
        select(Alert).where(Alert.id == uuid.UUID(alert_id))
    )
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert.to_dict()


@router.patch("/{alert_id}/status")
async def update_alert_status(
    alert_id: str,
    body: StatusUpdate,
    db: AsyncSession = Depends(get_db),
):
    """
    Transition an alert's status.
    Valid transitions:
      NEW → ACKNOWLEDGED → INVESTIGATING → RESOLVED
    Cannot go backwards.
    """
    result = await db.execute(
        select(Alert).where(Alert.id == uuid.UUID(alert_id))
    )
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    new_status = body.status.upper()

    # Validate transition
    allowed = VALID_TRANSITIONS.get(alert.status, [])
    if new_status not in allowed:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot transition from {alert.status} to {new_status}. "
                   f"Allowed: {allowed}",
        )

    # Apply transition
    alert.status = new_status
    now = datetime.now(timezone.utc)

    if new_status == "ACKNOWLEDGED":
        alert.acknowledged_at = now
    elif