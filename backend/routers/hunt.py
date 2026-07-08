"""
routers/hunt.py — Threat hunting: ad-hoc filter builder + saved hunts.

A "hunt" is a set of conditions (field, operator, value) combined with
AND or OR, run against the logs table. Users can preview results live,
save a named hunt for reuse, or promote a hunt into a real alert rule.
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, or_, and_, func
from sqlalchemy.orm import Session
from database import get_db
from models import Log, SavedHunt, AlertRule, AlertSeverity

router = APIRouter(tags=["threat-hunting"])

ALLOWED_FIELDS = {
    "source_ip", "source_type", "level", "status_code",
    "action", "message", "source_host", "user",
}
ALLOWED_OPERATORS = {"=", "!=", "contains", ">", "<", "regex"}


class Condition(BaseModel):
    field: str
    operator: str
    value: str


class HuntQuery(BaseModel):
    conditions: list[Condition] = []
    combinator: str = "AND"
    page: int = 1
    page_size: int = 50


class SaveHuntBody(BaseModel):
    name: str
    filters: HuntQuery


def _build_condition(cond: Condition):
    if cond.field not in ALLOWED_FIELDS:
        raise HTTPException(status_code=400, detail=f"Unsupported field: {cond.field}")
    if cond.operator not in ALLOWED_OPERATORS:
        raise HTTPException(status_code=400, detail=f"Unsupported operator: {cond.operator}")

    col = getattr(Log, cond.field)

    if cond.operator == "=":
        try:
            return col == int(cond.value)
        except ValueError:
            return col == cond.value
    if cond.operator == "!=":
        try:
            return col != int(cond.value)
        except ValueError:
            return col != cond.value
    if cond.operator == "contains":
        return col.ilike(f"%{cond.value}%")
    if cond.operator == ">":
        return col > float(cond.value)
    if cond.operator == "<":
        return col < float(cond.value)
    if cond.operator == "regex":
        return col.op("~")(cond.value)
    raise HTTPException(status_code=400, detail="Unhandled operator")


def _run_query(db: Session, query: HuntQuery):
    if not query.conditions:
        where = True
    else:
        clauses = [_build_condition(c) for c in query.conditions]
        where = or_(*clauses) if query.combinator.upper() == "OR" else and_(*clauses)

    total = db.execute(select(func.count()).select_from(Log).where(where)).scalar_one()
    offset = (query.page - 1) * query.page_size
    rows = db.execute(
        select(Log).where(where).order_by(Log.timestamp.desc())
        .offset(offset).limit(query.page_size)
    ).scalars().all()

    return {
        "total": total,
        "page": query.page,
        "page_size": query.page_size,
        "logs": [r.to_dict() for r in rows],
    }


@router.post("/hunt/preview")
async def preview_hunt(query: HuntQuery, db: Session = Depends(get_db)):
    """Dry-run a filter set against logs without saving anything."""
    return _run_query(db, query)


@router.post("/hunts")
async def save_hunt(body: SaveHuntBody, db: Session = Depends(get_db)):
    hunt = SavedHunt(name=body.name, filters_json=body.filters.dict())
    db.add(hunt)
    db.commit()
    return hunt.to_dict()


@router.get("/hunts")
async def list_hunts(db: Session = Depends(get_db)):
    hunts = db.query(SavedHunt).order_by(SavedHunt.created_at.desc()).all()
    return {"hunts": [h.to_dict() for h in hunts]}


@router.delete("/hunts/{hunt_id}")
async def delete_hunt(hunt_id: int, db: Session = Depends(get_db)):
    hunt = db.query(SavedHunt).filter(SavedHunt.id == hunt_id).first()
    if not hunt:
        raise HTTPException(status_code=404, detail="Hunt not found")
    db.delete(hunt)
    db.commit()
    return {"deleted": True}


@router.post("/hunts/{hunt_id}/create-rule")
async def create_rule_from_hunt(hunt_id: int, db: Session = Depends(get_db)):
    """
    Promote a saved hunt's first condition into a real alert rule with
    sensible defaults. The analyst can refine threshold/window afterward
    via the normal rule CRUD endpoints.
    """
    hunt = db.query(SavedHunt).filter(SavedHunt.id == hunt_id).first()
    if not hunt:
        raise HTTPException(status_code=404, detail="Hunt not found")

    conditions = hunt.filters_json.get("conditions", [])
    if not conditions:
        raise HTTPException(status_code=400, detail="Hunt has no conditions to convert")

    first = conditions[0]
    op_map = {"=": "eq", "!=": "eq", "contains": "contains", ">": "gt", "<": "lt"}
    condition_operator = op_map.get(first["operator"], "eq")

    rule = AlertRule(
        name=f"From Hunt: {hunt.name}",
        description=f"Auto-created from saved hunt '{hunt.name}'",
        condition_field=first["field"],
        condition_operator=condition_operator,
        condition_value=first["value"],
        severity=AlertSeverity.MEDIUM,
        time_window_seconds=300,
        threshold_count=5,
        cooldown_seconds=300,
        enabled=True,
    )
    db.add(rule)
    db.commit()
    return rule.to_dict()