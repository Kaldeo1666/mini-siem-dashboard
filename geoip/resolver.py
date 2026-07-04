"""
geoip/resolver.py — IP -> country resolution using the bundled GeoLite2 database.

How this works (analogy): think of the .mmdb file as a big phonebook that maps
IP addresses to countries. Looking it up on disk is fast, but doing it on every
single request is wasteful if we've already looked up that IP recently. So we
keep a "sticky note" cache in the geoip_cache table: check the sticky note
first, and only open the phonebook if the note is missing or older than 7 days.
"""

import datetime
import geoip2.database
import geoip2.errors

from sqlalchemy import select
from sqlalchemy.orm import Session

from models import GeoIPCache

# Path inside the container (see docker-compose.yml: ./geoip -> /app/geoip)
_MMDB_PATH = "/app/geoip/GeoLite2-Country.mmdb"

# Load the database file once, when this module is first imported,
# rather than opening it fresh on every lookup.
_reader = geoip2.database.Reader(_MMDB_PATH)

CACHE_TTL_DAYS = 7


def resolve_ip(db: Session, ip: str) -> dict:
    """
    Resolve an IP to {"country_code": ..., "country_name": ..., "city": None}.

    Checks geoip_cache first (if the entry exists and isn't older than
    CACHE_TTL_DAYS). Falls back to the GeoLite2 database file, then writes
    the result back into geoip_cache for next time.

    Returns a dict with all three keys, using None for anything unknown
    (private IPs, lookup misses, etc.) rather than raising an error, since
    a failed GeoIP lookup should never break log ingestion.
    """
    if not ip:
        return {"country_code": None, "country_name": None, "city": None}

    # 1. Check the cache first
    cached = db.execute(
        select(GeoIPCache).where(GeoIPCache.ip == ip)
    ).scalar_one_or_none()

    if cached:
        age = datetime.datetime.now(datetime.timezone.utc) - cached.cached_at
        if age.days < CACHE_TTL_DAYS:
            return {
                "country_code": cached.country_code,
                "country_name": cached.country_name,
                "city": cached.city,
            }

    # 2. Not cached (or expired) -> look it up in the .mmdb file
    result = {"country_code": None, "country_name": None, "city": None}
    try:
        response = _reader.country(ip)
        result["country_code"] = response.country.iso_code
        result["country_name"] = response.country.name
        # City lookups aren't available in the Country-only database we have.
    except (geoip2.errors.AddressNotFoundError, ValueError):
        # Private/reserved IPs (10.x, 192.168.x, etc.) or malformed input.
        # This is expected and not an error worth logging loudly.
        pass

    # 3. Write back to the cache (upsert-style: update if exists, else insert)
    if cached:
        cached.country_code = result["country_code"]
        cached.country_name = result["country_name"]
        cached.city = result["city"]
        cached.cached_at = datetime.datetime.now(datetime.timezone.utc)
    else:
        db.add(GeoIPCache(
            ip=ip,
            country_code=result["country_code"],
            country_name=result["country_name"],
            city=result["city"],
        ))
    db.commit()

    return result
