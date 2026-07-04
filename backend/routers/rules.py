"""
routers/rules.py — Alert rule CRUD + built-in rule seeding.

GET    /rules              — list all rules
POST   /rules              — create a rule
GET    /rules/{id}         — get one rule
PUT    /rules/{id}         — update a rule
DELETE /rules/{id}         — delete a rule
PATCH  /rules/{id}/toggle  — enable/disable
"""

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models import AlertRule

router = APIRouter(prefix="/rules", tags=["rules"])
# Maps public API field names (used in request/response JSON) to the
# actual database column names, since they differ slightly.
FIELD_MAP = {"threshold": "threshold_count", "window_seconds": "time_window_seconds"}

def _map_fields(data: dict) -> dict:
    return {FIELD_MAP.get(k, k): v for k, v in data.items()}


# ── Pydantic schemas (request/response shapes) ────────────────────────────────
# Pydantic validates incoming JSON automatically — if a required field is
# missing or the wrong type, FastAPI returns a 422 error before your code runs.

class RuleCreate(BaseModel):
    name: str
    description: str | None = None
    condition_type: str
    condition_field: str
    condition_value: str
    group_by: str | None = None
    threshold: int = 1
    window_seconds: int = 60
    severity: str
    mitre_technique_id: str | None = None
    enabled: bool = True
    cooldown_seconds: int = 300


class RuleUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    condition_type: str | None = None
    condition_field: str | None = None
    condition_value: str | None = None
    group_by: str | None = None
    threshold: int | None = None
    window_seconds: int | None = None
    severity: str | None = None
    mitre_technique_id: str | None = None
    enabled: bool | None = None
    cooldown_seconds: int | None = None


# ── Built-in rules ────────────────────────────────────────────────────────────
# These 5 rules are seeded into the DB at startup if they don't exist yet.
# Each maps to a real MITRE ATT&CK technique.

BUILTIN_RULES = [
    {
        "name": "Brute Force Login",
        "description": "Same IP fails login 10+ times in 60 seconds",
        "condition_type": "threshold",
        "condition_field": "status_code",
        "condition_value": "401,403",
        "group_by": "source_ip",
        "threshold": 10,
        "window_seconds": 60,
        "severity": "CRITICAL",
        "mitre_technique_id": "T1110",
        "cooldown_seconds": 300,
    },
    {
        "name": "New Admin IP",
        "description": "New IP address accessing admin routes",
        "condition_type": "new_entity",
        "condition_field": "source_ip",
        "condition_value": "/admin",
        "group_by": "source_ip",
        "threshold": 1,
        "window_seconds": 86400,
        "severity": "HIGH",
        "mitre_technique_id": "T1078",
        "cooldown_seconds": 3600,
    },
    {
        "name": "HTTP 500 Spike",
        "description": "More than 20 server errors per minute from same host",
        "condition_type": "rate",
        "condition_field": "status_code",
        "condition_value": "500",
        "group_by": "source_host",
        "threshold": 20,
        "window_seconds": 60,
        "severity": "MEDIUM",
        "mitre_technique_id": "T1499",
        "cooldown_seconds": 300,
    },
    {
        "name": "Port Scan Signature",
        "description": "50+ 404 responses from same IP in 30 seconds",
        "condition_type": "threshold",
        "condition_field": "status_code",
        "condition_value": "404",
        "group_by": "source_ip",
        "threshold": 50,
        "window_seconds": 30,
        "severity": "HIGH",
        "mitre_technique_id": "T1046",
        "cooldown_seconds": 600,
    },
    {
        "name": "Large Exfiltration",
        "description": "Log message indicates large data transfer (>10MB)",
        "condition_type": "pattern_match",
        "condition_field": "message",
        "condition_value": "exfil|bytes_sent|large.transfer|10485760",
        "group_by": "source_ip",
        "threshold": 1,
        "window_seconds": 300,
        "severity": "CRITICAL",
        "mitre_technique_id": "T1041",
        "cooldown_seconds": 600,
    },
]


async def seed_builtin_rules(db: AsyncSession):
    """Insert built-in rules if they don't already exist (checked by name)."""
    for rule_data in BUILTIN_RULES:
        existing = db.execute(
            select(AlertRule).where(AlertRule.name == rule_data["name"])
        )
        if existing.scalar_one_or_none() is None:
            db.add(AlertRule(**_map_fields(rule_data)))
    db.commit()


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("")
async def list_rules(db: AsyncSession = Depends(get_db)):
    """Return all alert rules ordered by severity."""
    result = db.execute(
        select(AlertRule).order_by(AlertRule.created_at.asc())
    )
    rules = result.scalars().all()
    return {"rules": [r.to_dict() for r in rules], "total": len(rules)}


@router.post("")
async def create_rule(body: RuleCreate, db: AsyncSession = Depends(get_db)):
    """Create a new alert rule."""
    rule = AlertRule(**_map_fields(body.model_dump()))
    db.add(rule)
    db.commit()
    return rule.to_dict()


@router.get("/{rule_id}")
async def get_rule(rule_id: str, db: AsyncSession = Depends(get_db)):
    """Get a single rule by ID."""
    result = db.execute(
        select(AlertRule).where(AlertRule.id == int(rule_id))
    )
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule.to_dict()


@router.put("/{rule_id}")
async def update_rule(
    rule_id: str, body: RuleUpdate, db: AsyncSession = Depends(get_db)
):
    """Update an existing rule. Only provided fields are changed."""
    result = db.execute(
        select(AlertRule).where(AlertRule.id == int(rule_id))
    )
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    # Only update fields that were actually provided in the request
    for field, value in _map_fields(body.model_dump(exclude_unset=True)).items():
        setattr(rule, field, value)

    rule.updated_at = datetime.now(timezone.utc)
    db.commit()
    return rule.to_dict()


@router.delete("/{rule_id}")
async def delete_rule(rule_id: str, db: AsyncSession = Depends(get_db)):
    """Delete a rule by ID."""
    result = db.execute(
        select(AlertRule).where(AlertRule.id == int(rule_id))
    )
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    db.delete(rule)
    db.commit()
    return {"deleted": rule_id}


@router.patch("/{rule_id}/toggle")
async def toggle_rule(rule_id: str, db: AsyncSession = Depends(get_db)):
    """Flip a rule between enabled and disabled."""
    result = db.execute(
        select(AlertRule).where(AlertRule.id == int(rule_id))
    )
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    rule.enabled = not rule.enabled
    rule.updated_at = datetime.now(timezone.utc)
    db.commit()
    return {"id": rule_id, "enabled": rule.enabled}

class RuleTestRequest(BaseModel):
    hours_back: int = 24


@router.post("/{rule_id}/test")
async def test_rule(
    rule_id: str,
    body: RuleTestRequest = RuleTestRequest(),
    db: AsyncSession = Depends(get_db),
):
    """
    Dry-run a rule against historical logs.
    Returns how many times it would have fired + sample matches.
    Does NOT create any real alerts.
    """
    from datetime import timedelta
    from sqlalchemy import func, and_
    from models import Log

    result = db.execute(
        select(AlertRule).where(AlertRule.id == int(rule_id))
    )
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    now = datetime.now(timezone.utc)
    window_start = now - timedelta(hours=body.hours_back)

    # Build conditions same as engine
    conditions = [Log.timestamp >= window_start]

    if rule.condition_type in ("threshold", "rate"):
        values = [v.strip() for v in rule.condition_value.split(",")]
        if rule.condition_field == "status_code":
            int_values = [int(v) for v in values if v.isdigit()]
            if int_values:
                conditions.append(Log.status_code.in_(int_values))
    elif rule.condition_type == "pattern_match":
        conditions.append(Log.message.op("~*")(rule.condition_value))
    elif rule.condition_type == "new_entity":
        conditions.append(Log.action.ilike(f"%{rule.condition_value}%"))

    where = and_(*conditions)

    # Get sample matches
    sample_result = db.execute(
        select(Log).where(where).order_by(Log.timestamp.desc()).limit(5)
    )
    samples = sample_result.scalars().all()

    # Count total matches
    count_result = db.execute(
        select(func.count()).select_from(Log).where(where)
    )
    total = count_result.scalar_one()

    # Would it have fired?
    would_fire = total >= rule.threshold_count

    return {
        "rule_name": rule.name,
        "would_have_fired": total if would_fire else 0,
        "total_matches": total,
        "threshold": rule.threshold_count,
        "evaluated_window": f"Last {body.hours_back} hours",
        "sample_matches": [s.to_dict() for s in samples],
    }



