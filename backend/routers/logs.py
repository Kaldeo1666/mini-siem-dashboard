"""
routers/logs.py — Query and retrieve stored logs.

GET /logs           — paginated log list with optional filters
GET /logs/stats     — summary counts (total, per source_type, per level)
"""

from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models import Log

router = APIRouter(prefix="/logs", tags=["logs"])


@router.get("")
async def get_logs(
    # ── Pagination ──────────────────────────────────────────────────
    page: int = Query(1, ge=1, description="Page number (1-based)"),
    page_size: int = Query(50, ge=1, le=100, description="Rows per page: 25, 50, or 100"),

    # ── Sorting ──────────────────────────────────────────────────────
    sort_by: str = Query("timestamp", description="Column to sort by"),
    sort_dir: Literal["asc", "desc"] = Query("desc", description="Sort direction"),

    # ── Filters ──────────────────────────────────────────────────────
    source_type: str | None = Query(None, description="Filter by source type"),
    level: str | None = Query(None, description="Filter by level"),
    source_ip: str | None = Query(None, description="Filter by exact source IP"),
    search: str | None = Query(None, description="Full-text search in message column"),

    # ── Time range ───────────────────────────────────────────────────
    time_from: datetime | None = Query(None, description="Start of time range (ISO 8601)"),
    time_to: datetime | None = Query(None, description="End of time range (ISO 8601)"),

    db: AsyncSession = Depends(get_db),
):
    """
    Returns a paginated, filterable list of logs.

    Example:
        GET /logs?page=1&page_size=50&source_type=apache&sort_by=timestamp&sort_dir=desc
        GET /logs?time_from=2026-05-28T00:00:00Z&level=ERROR
    """
    # Build WHERE conditions
    conditions = []
    if source_type:
        conditions.append(Log.source_type == source_type)
    if level:
        conditions.append(Log.level == level.upper())
    if source_ip:
        conditions.append(Log.source_ip == source_ip)
    if search:
        conditions.append(Log.message.ilike(f"%{search}%"))
    if time_from:
        conditions.append(Log.timestamp >= time_from)
    if time_to:
        conditions.append(Log.timestamp <= time_to)

    where = and_(*conditions) if conditions else True

    # Count total matching rows (for pagination metadata)
    count_result = await db.execute(
        select(func.count()).select_from(Log).where(where)
    )
    total = count_result.scalar_one()

    # Build ORDER BY
    sortable_columns = {
        "timestamp": Log.timestamp,
        "source_type": Log.source_type,
        "source_host": Log.source_host,
        "level": Log.level,
        "source_ip": Log.source_ip,
        "status_code": Log.status_code,
        "ingested_at": Log.ingested_at,
    }
    sort_col = sortable_columns.get(sort_by, Log.timestamp)
    order = sort_col.asc() if sort_dir == "asc" else sort_col.desc()

    # Fetch the page
    offset = (page - 1) * page_size
    result = await db.execute(
        select(Log).where(where).order_by(order).offset(offset).limit(page_size)
    )
    rows = result.scalars().all()

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": max(1, -(-total // page_size)),  # ceiling division
        "logs": [row.to_dict() for row in rows],
    }


@router.get("/stats")
async def get_stats(db: AsyncSession = Depends(get_db)):
    """
    Returns a quick summary:
    - total log count
    - counts grouped by source_type
    - counts grouped by level
    """
    total = (await db.execute(select(func.count()).select_from(Log))).scalar_one()

    by_source = await db.execute(
        select(Log.source_type, func.count().label("count"))
        .group_by(Log.source_type)
        .order_by(func.count().desc())
    )

    by_level = await db.execute(
        select(Log.level, func.count().label("count"))
        .group_by(Log.level)
        .order_by(func.count().desc())
    )

    return {
        "total": total,
        "by_source_type": [{"source_type": r[0], "count": r[1]} for r in by_source],
        "by_level": [{"level": r[0], "count": r[1]} for r in by_level],
    }
