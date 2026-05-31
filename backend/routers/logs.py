from datetime import datetime
from typing import Literal
from sqlalchemy import select, func, and_, cast
from sqlalchemy.dialects.postgresql import INET as PG_INET
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from database import get_db
from models import Log

router = APIRouter(prefix="/logs", tags=["logs"])

@router.get("")
async def get_logs(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    sort_by: str = Query("timestamp"),
    sort_dir: Literal["asc", "desc"] = Query("desc"),
    source_type: str | None = Query(None),
    level: str | None = Query(None),
    source_ip: str | None = Query(None),
    search: str | None = Query(None),
    time_from: datetime | None = Query(None),
    time_to: datetime | None = Query(None),
    db: AsyncSession = Depends(get_db),
):
    conditions = []
    if source_type:
        conditions.append(Log.source_type == source_type)
    if level:
        conditions.append(Log.level == level.upper())
    if source_ip:
        conditions.append(cast(Log.source_ip, PG_INET) == cast(source_ip, PG_INET))
    if search:
        conditions.append(Log.message.ilike(f"%{search}%"))
    if time_from:
        conditions.append(Log.timestamp >= time_from)
    if time_to:
        conditions.append(Log.timestamp <= time_to)

    where = and_(*conditions) if conditions else True

    count_result = await db.execute(
        select(func.count()).select_from(Log).where(where)
    )
    total = count_result.scalar_one()

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

    offset = (page - 1) * page_size
    result = await db.execute(
        select(Log).where(where).order_by(order).offset(offset).limit(page_size)
    )
    rows = result.scalars().all()

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": max(1, -(-total // page_size)),
        "logs": [row.to_dict() for row in rows],
    }


@router.get("/stats")
async def get_stats(db: AsyncSession = Depends(get_db)):
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