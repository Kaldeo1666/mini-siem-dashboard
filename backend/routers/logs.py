from datetime import datetime, timezone, timedelta
from typing import Literal
from sqlalchemy import select, func, and_, cast
from sqlalchemy.dialects.postgresql import INET as PG_INET
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from database import get_db
from models import Log, GeoIPCache

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

    count_result = db.execute(
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
    result = db.execute(
        select(Log).where(where).order_by(order).offset(offset).limit(page_size)
    )
    rows = result.scalars().all()

    # Batch-enrich this page with GeoIP country data (looked up from
    # geoip_cache — never stored on the Log row itself, per V3 Day 1 design)
    ip_list = list({str(r.source_ip) for r in rows if r.source_ip})
    geo_map = {}
    if ip_list:
        geo_rows = db.execute(
            select(GeoIPCache).where(GeoIPCache.ip.in_(ip_list))
        ).scalars().all()
        geo_map = {str(g.ip): g for g in geo_rows}

    logs_out = []
    for row in rows:
        d = row.to_dict()
        geo = geo_map.get(d["source_ip"])
        d["country_code"] = geo.country_code if geo else None
        d["country_name"] = geo.country_name if geo else None
        logs_out.append(d)

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": max(1, -(-total // page_size)),
        "logs": logs_out,
    }


@router.get("/events-per-minute")
async def events_per_minute(
    minutes: int = Query(60, ge=1, le=1440),
    db: AsyncSession = Depends(get_db),
):
    """
    Events/minute time series bucketed per source_type, for the last
    `minutes` minutes. Powers the dashboard's live line chart.
    """
    window_start = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    bucket = func.date_trunc("minute", Log.timestamp).label("minute")

    rows = db.execute(
        select(bucket, Log.source_type, func.count().label("count"))
        .where(Log.timestamp >= window_start)
        .group_by(bucket, Log.source_type)
        .order_by(bucket)
    ).all()

    return {
        "minutes": minutes,
        "data": [
            {
                "minute": r[0].isoformat() if r[0] else None,
                "source_type": r[1],
                "count": r[2],
            }
            for r in rows
        ],
    }


@router.get("/top-ips")
async def top_source_ips(
    hours: int = Query(1, ge=1, le=24),
    limit: int = Query(10, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
):
    """
    Top source IPs by event count in the last `hours` hours, enriched
    with country data from geoip_cache. Powers the dashboard's top-10 table.
    """
    window_start = datetime.now(timezone.utc) - timedelta(hours=hours)

    rows = db.execute(
        select(Log.source_ip, func.count().label("count"))
        .where(Log.timestamp >= window_start, Log.source_ip.isnot(None))
        .group_by(Log.source_ip)
        .order_by(func.count().desc())
        .limit(limit)
    ).all()

    ip_list = [str(ip) for ip, _ in rows]
    geo_map = {}
    if ip_list:
        geo_rows = db.execute(
            select(GeoIPCache).where(GeoIPCache.ip.in_(ip_list))
        ).scalars().all()
        geo_map = {str(g.ip): g for g in geo_rows}

    top_ips = []
    for ip, count in rows:
        ip_str = str(ip)
        geo = geo_map.get(ip_str)
        top_ips.append({
            "source_ip": ip_str,
            "count": count,
            "country_code": geo.country_code if geo else None,
            "country_name": geo.country_name if geo else None,
        })

    return {"hours": hours, "top_ips": top_ips}


@router.get("/stats")
async def get_stats(db: AsyncSession = Depends(get_db)):
    total = (db.execute(select(func.count()).select_from(Log))).scalar_one()

    by_source = db.execute(
        select(Log.source_type, func.count().label("count"))
        .group_by(Log.source_type)
        .order_by(func.count().desc())
    )
    by_level = db.execute(
        select(Log.level, func.count().label("count"))
        .group_by(Log.level)
        .order_by(func.count().desc())
    )

    return {
        "total": total,
        "by_source_type": [{"source_type": r[0], "count": r[1]} for r in by_source],
        "by_level": [{"level": r[0], "count": r[1]} for r in by_level],
    }
