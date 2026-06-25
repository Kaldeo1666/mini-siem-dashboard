"""
anomaly_engine.py - Detects anomalies by comparing live traffic to baselines.

Anomaly Type 1: Traffic volume spike
Anomaly Type 2: Unusual hour activity
Anomaly Type 3: New user agent string
Anomaly Type 4: Impossible travel
"""

from datetime import datetime, timezone, timedelta
from sqlalchemy import func, and_, text
from database import SessionLocal
from models import Alert, AlertSeverity, AlertStatus, Baseline, Log, SeenUserAgent
import re


def detect_anomalies():
    """Main function - called every 30 seconds by APScheduler."""
    db = SessionLocal()
    try:
        _detect_traffic_spikes(db)
        _detect_unusual_hour_activity(db)
        _detect_new_user_agents(db)
        _detect_impossible_travel(db)
    except Exception as e:
        print(f"[Anomaly] Error during detection: {e}")
    finally:
        db.close()


def _fire_anomaly_alert(db, rule_name, severity, source_type, source_ip,
                        description, mitre_technique_id, cooldown_minutes=60):
    """Fire an anomaly alert with deduplication."""
    cooldown_start = datetime.now(timezone.utc) - timedelta(minutes=cooldown_minutes)

    existing = (
        db.query(Alert)
        .filter(
            and_(
                Alert.rule_name == rule_name,
                Alert.source_type == source_type,
                Alert.status != AlertStatus.RESOLVED,
                Alert.triggered_at >= cooldown_start,
            )
        )
        .first()
    )

    if existing:
        return False

    alert = Alert(
        rule_id=None,
        rule_name=rule_name,
        severity=severity,
        status=AlertStatus.NEW,
        source_ip=source_ip,
        source_type=source_type,
        description=description,
        mitre_technique_id=mitre_technique_id,
    )
    db.add(alert)
    db.commit()
    print(f"[Anomaly] Alert fired: {rule_name} | {source_type} | {severity}")
    return True


def _detect_traffic_spikes(db):
    """Anomaly Type 1: Traffic volume spike using 3-sigma rule."""
    now = datetime.now(timezone.utc)
    one_minute_ago = now - timedelta(minutes=1)
    hour_of_day = now.hour
    day_of_week = now.weekday()

    counts = (
        db.query(Log.source_type, func.count().label("cnt"))
        .filter(Log.timestamp >= one_minute_ago)
        .group_by(Log.source_type)
        .all()
    )

    for source_type, current_count in counts:
        baseline = (
            db.query(Baseline)
            .filter(
                Baseline.metric_name == "events_per_minute",
                Baseline.source_type == source_type,
                Baseline.hour_of_day == hour_of_day,
                Baseline.day_of_week == day_of_week,
                Baseline.sample_count >= 10,
            )
            .first()
        )

        if not baseline:
            continue

        threshold = baseline.avg_value + (3 * baseline.stddev_value)

        if current_count > threshold and threshold > 0:
            description = (
                f"Traffic spike detected for {source_type}: "
                f"{current_count} events/min vs baseline avg "
                f"{baseline.avg_value:.1f} (threshold: {threshold:.1f})"
            )
            _fire_anomaly_alert(
                db=db,
                rule_name=f"Traffic Volume Spike - {source_type}",
                severity=AlertSeverity.HIGH,
                source_type=source_type,
                source_ip=None,
                description=description,
                mitre_technique_id="T1498",
                cooldown_minutes=60,
            )


def _detect_unusual_hour_activity(db):
    """Anomaly Type 2: Login during normally silent hours."""
    now = datetime.now(timezone.utc)
    five_minutes_ago = now - timedelta(minutes=5)
    hour_of_day = now.hour
    day_of_week = now.weekday()

    login_events = (
        db.query(Log.source_type, Log.source_ip, Log.user)
        .filter(
            and_(
                Log.timestamp >= five_minutes_ago,
                (Log.action.ilike("%/login%")) | (Log.user.isnot(None))
            )
        )
        .all()
    )

    if not login_events:
        return

    for source_type, source_ip, user in login_events:
        baseline = (
            db.query(Baseline)
            .filter(
                Baseline.metric_name == "events_per_minute",
                Baseline.source_type == source_type,
                Baseline.hour_of_day == hour_of_day,
                Baseline.day_of_week == day_of_week,
                Baseline.sample_count >= 10,
                Baseline.avg_value == 0.0,
            )
            .first()
        )

        if not baseline:
            continue

        description = (
            f"Login activity detected at hour {hour_of_day} "
            f"for {source_type} - baseline shows this hour is normally silent. "
            f"User: {user or 'unknown'}"
        )

        _fire_anomaly_alert(
            db=db,
            rule_name=f"Unusual Hour Login - {source_type}",
            severity=AlertSeverity.MEDIUM,
            source_type=source_type,
            source_ip=str(source_ip) if source_ip else None,
            description=description,
            mitre_technique_id="T1078",
            cooldown_minutes=60,
        )


def _detect_new_user_agents(db):
    """
    Anomaly Type 3: New user agent string detected.

    We extract user agent from the message field using a simple pattern.
    Every new unique user agent gets added to seen_user_agents table.
    If more than 5 new agents appear in one minute, suppress (bulk import).
    """
    now = datetime.now(timezone.utc)
    one_minute_ago = now - timedelta(minutes=1)

    # Get recent logs that have a user agent pattern in the message
    # Common log format: "GET /path HTTP/1.1" "Mozilla/5.0..."
    recent_logs = (
        db.query(Log.source_type, Log.message, Log.source_ip)
        .filter(
            and_(
                Log.timestamp >= one_minute_ago,
                Log.message.isnot(None),
                # Look for common user agent patterns in message
                Log.message.ilike("%Mozilla%") |
                Log.message.ilike("%curl%") |
                Log.message.ilike("%python%") |
                Log.message.ilike("%bot%") |
                Log.message.ilike("%scanner%")
            )
        )
        .all()
    )

    if not recent_logs:
        return

    # Extract user agents and check if new
    new_agents_this_minute = 0
    ua_pattern = re.compile(r'"([^"]*(?:Mozilla|curl|python|bot|scanner)[^"]*)"', re.IGNORECASE)

    for source_type, message, source_ip in recent_logs:
        if not message:
            continue

        match = ua_pattern.search(message)
        if not match:
            continue

        user_agent = match.group(1)[:500]

        # Check if we've seen this user agent before
        existing = (
            db.query(SeenUserAgent)
            .filter(
                SeenUserAgent.user_agent == user_agent,
                SeenUserAgent.source_type == source_type,
            )
            .first()
        )

        if not existing:
            # New user agent - add to seen list
            seen = SeenUserAgent(
                user_agent=user_agent,
                source_type=source_type,
            )
            db.add(seen)
            db.commit()
            new_agents_this_minute += 1

            # Suppress if bulk import scenario (more than 5 new agents/minute)
            if new_agents_this_minute > 5:
                print(f"[Anomaly] Suppressing new user agent alerts - bulk import detected")
                return

            description = (
                f"New user agent string detected for {source_type}: "
                f"{user_agent[:100]}"
            )
            _fire_anomaly_alert(
                db=db,
                rule_name=f"New User Agent - {source_type}",
                severity=AlertSeverity.LOW,
                source_type=source_type,
                source_ip=str(source_ip) if source_ip else None,
                description=description,
                mitre_technique_id="T1036",
                cooldown_minutes=60,
            )


def _get_country(ip_str):
    """
    Look up the country code for an IP address using GeoLite2.
    Returns country code like 'US', 'IN', or None if lookup fails.
    """
    try:
        import geoip2.database
        import os
        db_path = os.path.join(os.path.dirname(__file__), '..', 'geoip', 'GeoLite2-Country.mmdb')
        # Try alternate path for Docker container
        if not os.path.exists(db_path):
            db_path = '/app/geoip/GeoLite2-Country.mmdb'
        if not os.path.exists(db_path):
            return None
        with geoip2.database.Reader(db_path) as reader:
            response = reader.country(ip_str)
            return response.country.iso_code
    except Exception:
        return None


def _detect_impossible_travel(db):
    """
    Anomaly Type 4: Impossible travel detection.

    If the same user appears from two different IPs in different countries
    within 600 seconds, fire a CRITICAL alert with MITRE T1078.

    Think of it like: if John logs in from India at 2pm and from USA at 2:05pm,
    that's physically impossible - someone stole John's credentials.
    """
    now = datetime.now(timezone.utc)
    ten_minutes_ago = now - timedelta(seconds=600)

    # Get login events from the last 10 minutes where user is set
    login_events = (
        db.query(Log.user, Log.source_ip, Log.timestamp, Log.source_type)
        .filter(
            and_(
                Log.timestamp >= ten_minutes_ago,
                Log.user.isnot(None),
                Log.source_ip.isnot(None),
                (Log.action.ilike("%/login%")) | (Log.user.isnot(None))
            )
        )
        .order_by(Log.user, Log.timestamp)
        .all()
    )

    if len(login_events) < 2:
        return

    # Group by user
    from collections import defaultdict
    user_events = defaultdict(list)
    for user, source_ip, timestamp, source_type in login_events:
        user_events[user].append({
            "ip": str(source_ip),
            "timestamp": timestamp,
            "source_type": source_type,
        })

    # Check each user's events for impossible travel
    for user, events in user_events.items():
        if len(events) < 2:
            continue

        for i in range(len(events)):
            for j in range(i + 1, len(events)):
                event_a = events[i]
                event_b = events[j]

                # Skip if same IP
                if event_a["ip"] == event_b["ip"]:
                    continue

                # Check time difference
                time_diff = abs(
                    (event_b["timestamp"] - event_a["timestamp"]).total_seconds()
                )
                if time_diff > 600:
                    continue

                # Look up countries
                country_a = _get_country(event_a["ip"])
                country_b = _get_country(event_b["ip"])

                # Only fire if both lookups succeeded and countries differ
                if not country_a or not country_b:
                    continue
                if country_a == country_b:
                    continue

                description = (
                    f"Impossible travel detected for user '{user}': "
                    f"logged in from {country_a} ({event_a['ip']}) "
                    f"and {country_b} ({event_b['ip']}) "
                    f"within {int(time_diff)} seconds"
                )

                _fire_anomaly_alert(
                    db=db,
                    rule_name=f"Impossible Travel - {user}",
                    severity=AlertSeverity.CRITICAL,
                    source_type=event_a["source_type"],
                    source_ip=event_a["ip"],
                    description=description,
                    mitre_technique_id="T1078",
                    cooldown_minutes=60,
                )