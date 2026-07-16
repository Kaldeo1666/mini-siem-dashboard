"""
auth.py — API key authentication (V4 Day 4).

All API endpoints require a valid X-API-Key header, except:
  - GET /health (liveness check, used by tests and monitoring)
  - GET/POST /auth/keys (protected separately by a master key instead)
  - /ws/alerts (browsers cannot attach custom headers to a WebSocket
    handshake — header-based auth doesn't apply to it as written.
    Query-param or subprotocol-based WS auth is a documented follow-up,
    not implemented today, rather than silently left unauthenticated
    without explanation.)

Keys are stored as SHA-256 hashes, never in plaintext.
"""

import hashlib
import os
import secrets
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import get_db
from models import ApiKey

router = APIRouter(prefix="/auth", tags=["auth"])

MASTER_API_KEY = os.getenv("MASTER_API_KEY", "master-key-change-in-prod")


def _hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()


def generate_and_seed_default_key(db: Session):
    """
    Seeds one usable API key at startup from the DEFAULT_API_KEY env var,
    if set and no keys exist yet. Purely for local dev/test ergonomics —
    docker-compose.yml sets a fixed dev value so the test suite (run via
    docker exec, which inherits the container's environment) can
    authenticate without a manual bootstrap step. Never rely on this in
    a real deployment.
    """
    default_raw = os.getenv("DEFAULT_API_KEY")
    if not default_raw:
        return
    if db.query(ApiKey).count() > 0:
        return
    key = ApiKey(key_hash=_hash_key(default_raw), name="default-dev-key", active=True)
    db.add(key)
    db.commit()
    print("[Auth] Seeded default dev API key from DEFAULT_API_KEY env var")


async def verify_api_key(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    db: Session = Depends(get_db),
):
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing X-API-Key header")

    key_hash = _hash_key(x_api_key)
    key = db.query(ApiKey).filter(ApiKey.key_hash == key_hash, ApiKey.active == True).first()
    if not key:
        raise HTTPException(status_code=401, detail="Invalid or inactive API key")

    key.last_used_at = datetime.now(timezone.utc)
    db.commit()
    return key


class KeyCreate(BaseModel):
    name: str


@router.post("/keys")
async def create_api_key(
    body: KeyCreate,
    x_master_key: str | None = Header(default=None, alias="X-Master-Key"),
    db: Session = Depends(get_db),
):
    """
    Issue a new API key. Protected by MASTER_API_KEY (separate from the
    standard X-API-Key check, since this endpoint is what creates those
    keys). The raw key is returned ONLY in this response — it cannot be
    retrieved again afterward.
    """
    if x_master_key != MASTER_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing X-Master-Key header")

    raw_key = secrets.token_urlsafe(32)
    key = ApiKey(key_hash=_hash_key(raw_key), name=body.name, active=True)
    db.add(key)
    db.commit()
    db.refresh(key)

    return {**key.to_dict(), "api_key": raw_key}


@router.get("/keys")
async def list_api_keys(
    x_master_key: str | None = Header(default=None, alias="X-Master-Key"),
    db: Session = Depends(get_db),
):
    """List issued keys (metadata only — hashes/raw keys never exposed)."""
    if x_master_key != MASTER_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing X-Master-Key header")
    keys = db.query(ApiKey).order_by(ApiKey.created_at.desc()).all()
    return {"keys": [k.to_dict() for k in keys]}