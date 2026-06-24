"""
anomaly_engine.py - Detects anomalies by comparing live traffic to baselines.

Anomaly Type 1: Traffic volume spike
  - When events/minute for a source_type exceeds avg + 3 * stddev
  - Fires HIGH alert with MITRE T1498 or T1190

Anomaly Type 2: Unusual hour activity
  - When a login event occurs during an hour where baseline avg = 0
    and sample_count >= 10 (meaning we have enough data to be confident)
  - Fires MEDIUM alert with MITRE T1078
"""

from datetime import datetime, timezone, timedelta
from sqlalchemy import func, and_, text
from database import SessionLocal
from models import Alert, AlertSeverity, AlertStatus, Baseline, Log


def detect_anomalies():
    """Main function - called every 30 seconds by APScheduler."""
    db = SessionLocal()
    try:
        _detect_traffic_spikes(db)
        _detect_unusual_hour_activity(db)
    except Exception as e:
        print(f"[Anomaly] Error during detection: {e}")
    finally:
        db.close()


def _fire_anomaly_alert(db, rule_name, severity, source_type, source_ip,
                         description, mitre_technique_id, cooldown_minutes=60):
    """
    Fire an anomaly alert with deduplication.
    Won't re-fire the same alert within cooldown_minutes.
    """
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
    """
    Anomaly Type 1: Traffic volume spike.

    For each source_type, count events in the last minute.
    Compare to the baseline for the current hour_of_day + day_of_week.
    If current > avg + 3 * stddev -> fire alert.

    The '3 * stddev' threshold is called the 3-sigma rule.
    Statistically, only 0.3% of normal traffic exceeds this.
    So if we see it, something unusual is almost certainly happening.
    """
    now = datetime.now(timezone.utc)
    one_minute_ago = now - timedelta(minutes=1)
    hour_of_day = now.hour
    day_of_week = now.weekday()

    # Count events per source_type in the last minute
    counts = (
        db.query(Log.source_type, func.count().label("cnt"))
        .filter(Log.timestamp >= one_minute_ago)
        .group_by(Log.source_type)
        .all()
    )

    for source_type, current_count in counts:
        # Get baseline for this source_type at this hour
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
            # No baseline yet - not enough data to detect anomalies
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
    """
    Anomaly Type 2: Unusual hour activity.

    Check for login-related events in the last 5 minutes.
    If a login occurred during an hour where baseline avg = 0
    and we have >= 10 samples (meaning this hour is reliably quiet),
    fire a MEDIUM alert.

    Login events = action contains '/login' OR user field is not null.
    """
    now = datetime.now(timezone.utc)
    five_minutes_ago = now - timedelta(minutes=5)
    hour_of_day = now.hour
    day_of_week = now.weekday()

    # Find login-related events in the last 5 minutes
    login_events = (
        db.query(Log.source_type, Log.source_ip, Log.user)
        .filter(
            and_(
                Log.timestamp >= five_minutes_ago,
                # Login = action contains /login OR user field is set
                (Log.action.ilike("%/login%")) | (Log.user.isnot(None))
            )
        )
        .all()
    )

    if not login_events:
        return

    for source_type, source_ip, user in login_events:
        # Check if this hour is normally silent
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
            f"for {source_type} — baseline shows this hour is normally silent. "
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