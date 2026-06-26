"""
routers/ioc.py - IOC (Indicator of Compromise) management endpoints.

GET    /iocs          - List all active IOCs
POST   /iocs          - Add a single IOC entry
POST   /iocs/bulk     - Upload newline-delimited list of IPs
DELETE /iocs/{id}     - Deactivate an IOC entry
"""

import ipaddress
import re
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
from database import get_db
from models import IOCEntry, IOCType

router = APIRouter(prefix="/iocs", tags=["IOC"])


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class IOCCreate(BaseModel):
    type: str
    value: str
    description: Optional[str] = None
    source: Optional[str] = None


class IOCBulkUpload(BaseModel):
    entries: str  # newline-delimited list of IPs
    source: Optional[str] = "bulk_upload"
    description: Optional[str] = None


# ── Validation helpers ────────────────────────────────────────────────────────

def _validate_ip(value: str) -> bool:
    """Check if value is a valid IP address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _validate_domain(value: str) -> bool:
    """Check if value looks like a valid domain."""
    pattern = re.compile(
        r'^(?:[a-zA-Z0-9]'
        r'(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)'
        r'+[a-zA-Z]{2,}$'
    )
    return bool(pattern.match(value))


def _validate_ioc(ioc_type: str, value: str):
    """Validate IOC value based on type. Raises HTTPException if invalid."""
    if ioc_type == "ip":
        if not _validate_ip(value):
            raise HTTPException(status_code=400, detail=f"Invalid IP address: {value}")
    elif ioc_type == "domain":
        if not _validate_domain(value):
            raise HTTPException(status_code=400, detail=f"Invalid domain: {value}")
    elif ioc_type == "hash":
        if len(value) not in [32, 40, 64]:
            raise HTTPException(status_code=400, detail=f"Invalid hash length: {value}")
    else:
        raise HTTPException(status_code=400, detail=f"Invalid IOC type: {ioc_type}")


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("")
def list_iocs(
    active_only: bool = True,
    ioc_type: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """List all IOC entries. Optionally filter by active status or type."""
    query = db.query(IOCEntry)
    if active_only:
        query = query.filter(IOCEntry.active == True)
    if ioc_type:
        query = query.filter(IOCEntry.type == ioc_type)
    iocs = query.order_by(IOCEntry.added_at.desc()).all()
    return {
        "total": len(iocs),
        "iocs": [
            {
                "id": ioc.id,
                "type": ioc.type,
                "value": ioc.value,
                "description": ioc.description,
                "source": ioc.source,
                "added_at": ioc.added_at,
                "active": ioc.active,
            }
            for ioc in iocs
        ]
    }


@router.post("")
def add_ioc(payload: IOCCreate, db: Session = Depends(get_db)):
    """Add a single IOC entry after validating format."""
    _validate_ioc(payload.type, payload.value)

    # Check for duplicate
    existing = (
        db.query(IOCEntry)
        .filter(
            IOCEntry.type == payload.type,
            IOCEntry.value == payload.value,
            IOCEntry.active == True,
        )
        .first()
    )
    if existing:
        raise HTTPException(status_code=409, detail=f"IOC already exists: {payload.value}")

    ioc = IOCEntry(
        type=payload.type,
        value=payload.value,
        description=payload.description,
        source=payload.source,
        active=True,
    )
    db.add(ioc)
    db.commit()
    db.refresh(ioc)

    return {"message": "IOC added successfully", "id": ioc.id}


@router.post("/bulk")
def bulk_upload_iocs(payload: IOCBulkUpload, db: Session = Depends(get_db)):
    """
    Upload a newline-delimited list of IP addresses.
    Skips invalid IPs and duplicates.
    Returns count of added vs skipped.
    """
    lines = [line.strip() for line in payload.entries.splitlines() if line.strip()]

    added = 0
    skipped = 0
    errors = []

    for ip_str in lines:
        # Skip comments
        if ip_str.startswith("#"):
            skipped += 1
            continue

        # Validate IP
        if not _validate_ip(ip_str):
            errors.append(f"Invalid IP: {ip_str}")
            skipped += 1
            continue

        # Check duplicate
        existing = (
            db.query(IOCEntry)
            .filter(IOCEntry.value == ip_str, IOCEntry.active == True)
            .first()
        )
        if existing:
            skipped += 1
            continue

        ioc = IOCEntry(
            type=IOCType.ip,
            value=ip_str,
            description=payload.description or "Bulk upload",
            source=payload.source,
            active=True,
        )
        db.add(ioc)
        added += 1

    db.commit()

    return {
        "message": f"Bulk upload complete",
        "added": added,
        "skipped": skipped,
        "errors": errors[:10],
    }


@router.delete("/{ioc_id}")
def deactivate_ioc(ioc_id: int, db: Session = Depends(get_db)):
    """Deactivate an IOC entry (soft delete - keeps record but marks inactive)."""
    ioc = db.query(IOCEntry).filter(IOCEntry.id == ioc_id).first()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")

    ioc.active = False
    db.commit()

    return {"message": f"IOC {ioc_id} deactivated successfully"}