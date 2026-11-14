"""Service layer for alert dispatch, acknowledgement, and lifecycle management."""

from uuid import uuid4
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from ..models.alert import Alert
from ..models.base import utc_now
from ..models.incident import Incident


def create_alert_for_incident(
    db: Session,
    incident: Incident,
    alert_type: str = "THREAT_INCIDENT_CORRELATED",
    message: str | None = None,
) -> Alert:
    """Generate an alert for a correlated incident with duplicate prevention.

    Prevents generating duplicate unacknowledged alerts for the same incident and alert type.
    """
    stmt = (
        select(Alert)
        .where(Alert.incident_id == incident.incident_id)
        .where(Alert.alert_type == alert_type)
        .where(Alert.is_acknowledged.is_(False))
    )
    existing = db.execute(stmt).scalar_one_or_none()
    if existing is not None:
        return existing

    if message is None:
        message = (
            f"Threat detected for identity {incident.user_id}: {incident.title} "
            f"(Severity: {incident.severity}, Score: {incident.risk_score})"
        )

    new_alert = Alert(
        alert_id=f"alt-{uuid4().hex[:16]}",
        incident_id=incident.incident_id,
        alert_type=alert_type,
        severity=incident.severity,
        message=message,
        is_acknowledged=False,
    )
    db.add(new_alert)
    db.commit()
    db.refresh(new_alert)
    return new_alert


def list_alerts(
    db: Session,
    severity: str | None = None,
    is_acknowledged: bool | None = None,
    incident_id: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[int, list[Alert]]:
    """Query alerts with filtering and pagination."""
    query = select(Alert)

    if severity:
        query = query.where(Alert.severity == severity.upper())
    if is_acknowledged is not None:
        query = query.where(Alert.is_acknowledged.is_(is_acknowledged))
    if incident_id:
        query = query.where(Alert.incident_id == incident_id)

    count_query = select(func.count()).select_from(query.subquery())
    total = db.execute(count_query).scalar_one()

    # Prioritize unacknowledged alerts by severity (CRITICAL, HIGH, MEDIUM, LOW) and recency
    ordered_query = (
        query.order_by(Alert.is_acknowledged.asc(), Alert.created_at.desc())
        .offset(offset)
        .limit(limit)
    )
    items = list(db.execute(ordered_query).scalars().all())
    return total, items


def get_alert_by_id(db: Session, alert_id: str) -> Alert | None:
    """Retrieve full alert details including linked incident."""
    stmt = (
        select(Alert)
        .options(selectinload(Alert.incident))
        .where(Alert.alert_id == alert_id)
    )
    return db.execute(stmt).scalar_one_or_none()


def acknowledge_alert(
    db: Session,
    alert_id: str,
    acknowledged_by: str | None = None,
) -> Alert | None:
    """Acknowledge an alert and record the analyst identity and timestamp."""
    alert = get_alert_by_id(db, alert_id)
    if alert is None:
        return None

    alert.is_acknowledged = True
    alert.acknowledged_by = acknowledged_by or "analyst"
    alert.acknowledged_at = utc_now()
    alert.updated_at = utc_now()

    db.commit()
    db.refresh(alert)
    return alert
