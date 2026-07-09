"""
routers/cases.py — Case management: group related alerts into investigations.

POST   /cases              create a case
GET    /cases               list cases (paginated)
GET    /cases/{id}           case detail: linked alerts + note timeline
PATCH  /cases/{id}           update title/description/status/assignee
POST   /cases/{id}/alerts    link an existing alert to this case
POST   /cases/{id}/notes     append a timestamped investigation note
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from database import get_db
from models import Case, CaseAlert, CaseNote, Alert, CaseStatus, AlertSeverity

router = APIRouter(prefix="/cases", tags=["case-management"])


class CaseCreate(BaseModel):
    title: str
    description: str | None = None
    severity: str | None = None
    assignee: str | None = None


class CaseUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    status: str | None = None
    assignee: str | None = None


class AddAlertBody(BaseModel):
    alert_id: int


class AddNoteBody(BaseModel):
    note: str
    author: str | None = None


@router.post("")
async def create_case(body: CaseCreate, db: Session = Depends(get_db)):
    severity = None
    if body.severity:
        try:
            severity = AlertSeverity(body.severity.upper())
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid severity: {body.severity}")

    case = Case(
        title=body.title,
        description=body.description,
        severity=severity,
        assignee=body.assignee,
    )
    db.add(case)
    db.commit()
    return case.to_dict()


@router.get("")
async def list_cases(
    status: str | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
):
    q = db.query(Case)
    if status:
        try:
            q = q.filter(Case.status == CaseStatus(status.upper()))
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status: {status}")

    total = q.with_entities(func.count()).scalar()
    offset = (page - 1) * page_size
    cases = q.order_by(Case.updated_at.desc()).offset(offset).limit(page_size).all()

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "cases": [c.to_dict() for c in cases],
    }


@router.get("/{case_id}")
async def get_case(case_id: int, db: Session = Depends(get_db)):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    linked_alert_ids = [ca.alert_id for ca in db.query(CaseAlert).filter(CaseAlert.case_id == case_id).all()]
    alerts = db.query(Alert).filter(Alert.id.in_(linked_alert_ids)).all() if linked_alert_ids else []
    notes = db.query(CaseNote).filter(CaseNote.case_id == case_id).order_by(CaseNote.created_at.asc()).all()

    result = case.to_dict()
    result["alerts"] = [a.to_dict() for a in alerts]
    result["notes"] = [n.to_dict() for n in notes]
    return result


@router.patch("/{case_id}")
async def update_case(case_id: int, body: CaseUpdate, db: Session = Depends(get_db)):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    if body.title is not None:
        case.title = body.title
    if body.description is not None:
        case.description = body.description
    if body.assignee is not None:
        case.assignee = body.assignee
    if body.status is not None:
        try:
            case.status = CaseStatus(body.status.upper())
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status: {body.status}")

    db.commit()
    return case.to_dict()


@router.post("/{case_id}/alerts")
async def add_alert_to_case(case_id: int, body: AddAlertBody, db: Session = Depends(get_db)):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    alert = db.query(Alert).filter(Alert.id == body.alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    existing = db.query(CaseAlert).filter(
        CaseAlert.case_id == case_id, CaseAlert.alert_id == body.alert_id
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="Alert already linked to this case")

    link = CaseAlert(case_id=case_id, alert_id=body.alert_id)
    db.add(link)
    db.commit()
    return {"linked": True, "case_id": case_id, "alert_id": body.alert_id}


@router.post("/{case_id}/notes")
async def add_case_note(case_id: int, body: AddNoteBody, db: Session = Depends(get_db)):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    note = CaseNote(case_id=case_id, note=body.note, author=body.author)
    db.add(note)
    db.commit()
    return note.to_dict()