"""
engine.py — Alert Rules Evaluation Engine

Runs every 30 seconds via APScheduler.
For each enabled rule:
  1. Query logs within the rule's time window
  2. Group by the rule's group_by field
  3. If count exceeds threshold → fire an alert
  4. Deduplicate — don't re-fire if same (rule_id, group_value) is active
"""

import re
from datetime import datetime, timezone, timedelta

from sqlalchemy import select, func, and_, text
from sqlalchemy.ext.asyncio import AsyncSession

from database import AsyncSessionLocal
from models import AlertRule, Alert, Log

# WebSocket manager — we'll fill this in later
ws_manager = None


async def evaluate_rules():
    """Main function — called every 30 seconds by APScheduler."""
    async with AsyncSessionLocal() as db:
        # Get all enabled rules
        result = await db.execute(
            select(AlertRule).where(AlertRule.enabled == True)
        )
        rules = result.scalars().all()

        fired = 0
        for rule in rules:
            try:
                count = await _evaluate_single_rule(db, rule)
                fired += count
            except Exception as e:
                print(f"[Engine] Error evaluating rule '{rule.name}': {e}")

        if fired:
            print(f"[Engine] Cycle complete — {fired} alert(s) fired")


async def _evaluate_single_rule(db: AsyncSession, rule: AlertRule) -> int:
    """
    Evaluate one rule against recent logs.
    Returns number of new alerts fired.
    """
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(seconds=rule.window_seconds)

    # Build base condition — filter logs within the time window
    conditions = [Log.timestamp >= window_start]

    # Add rule-specific condition based on condition_type
    if rule.condition_type == "threshold":
        # e.g. status_code IN (401, 403)
        values = [v.strip() for v in rule.condition_value.split(",")]
        if rule.condition_field == "status_code":
            int_values = [int(v) for v in values if v.isdigit()]
            if int_values:
                conditions.append(Log.status_code.in_(int_values))
        else:
            conditions.append(
                getattr(Log, rule.condition_field, Log.message).in_(values)
            )

    elif rule.condition_type == "rate":
        # Same as threshold but focused on rate per minute
        values = [v.strip() for v in rule.condition_value.split(",")]
        if rule.condition_field == "status_code":
            int_values = [int(v) for v in values if v.isdigit()]
            if int_values:
                conditions.append(Log.status_code.in_(int_values))

    elif rule.condition_type == "pattern_match":
        # Regex/keyword match on message field
        pattern = rule.condition_value
        conditions.append(Log.message.op("~*")(pattern))

    elif rule.condition_type == "new_entity":
        # Check if source_ip has been seen before the window
        conditions.append(
            Log.action.ilike(f"%{rule.condition_value}%")
        )

    where = and_(*conditions)

    # Group by the rule's group_by field if set
    group_field = rule.group_by
    if group_field and hasattr(Log, group_field):
        col = getattr(Log, group_field)
        rows = await db.execute(
            select(col, func.count().label("cnt"))
            .where(where)
            .group_by(col)
            .having(func.count() >= rule.threshold)
        )
        matches = rows.all()
    else:
        # No grouping — just count total
        count_result = await db.execute(
            select(func.count()).select_from(Log).where(where)
        )
        total = count_result.scalar_one()
        matches = [(None, total)] if total >= rule.threshold else []

    # Fire alerts for each matching group
    fired = 0
    for group_value, matched_count in matches:
        group_str = str(group_value) if group_value is not None else "global"
        did_fire = await _fire_alert(db, rule, group_str, matched_count, now)
        if did_fire:
            fired += 1

    return fired


async def _fire_alert(
    db: AsyncSession,
    rule: AlertRule,
    group_value: str,
    matched_count: int,
    now: datetime,
) -> bool:
    """
    Fire an alert if deduplication allows it.
    Returns True if a new alert was created or updated.
    """
    # Check for existing active alert for same (rule_id, group_value)
    existing_result = await db.execute(
        select(Alert).where(
            and_(
                Alert.rule_id == rule.id,
                Alert.group_value == group_value,
                Alert.status != "RESOLVED",
            )
        )
    )
    existing = existing_result.scalar_one_or_none()

    if existing:
        # Check cooldown
        time_since = (now - existing.last_seen).total_seconds()
        if time_since < rule.cooldown_seconds:
            # Within cooldown — just update count and last_seen
            existing.matched_count += matched_count
            existing.last_seen = now
            await db.commit()
            return False  # not a new alert
        else:
            # Cooldown expired — allow re-fire only if resolved
            # (already checked status != RESOLVED above, so skip)
            existing.matched_count += matched_count
            existing.last_seen = now
            await db.commit()
            return False

    # No existing alert — create a new one
    alert = Alert(
        rule_id=rule.id,
        rule_name=rule.name,
        severity=rule.severity,
        status="NEW",
        group_value=group_value,
        matched_count=matched_count,
        first_seen=now,
        last_seen=now,
        mitre_technique_id=rule.mitre_technique_id,
    )
    db.add(alert)
    await db.commit()

    print(f"[Engine] 🚨 Alert fired: '{rule.name}' | {group_value} | {rule.severity}")

    # Push to WebSocket clients if manager is connected
    if ws_manager:
        await ws_manager.broadcast(alert.to_dict())

    return True