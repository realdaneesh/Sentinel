"""Service layer for incident management and investigation workflows."""

from datetime import datetime
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from ..models.base import utc_now
from ..models.incident import Incident


def list_incidents(
    db: Session,
    user_id: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    min_risk_score: int | None = None,
    max_risk_score: int | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[int, list[Incident]]:
    """List incidents with filtering and pagination."""
    query = select(Incident)

    if user_id:
        query = query.where(Incident.user_id == user_id)
    if severity:
        query = query.where(Incident.severity == severity.upper())
    if status:
        query = query.where(Incident.status == status.lower())
    if min_risk_score is not None:
        query = query.where(Incident.risk_score >= min_risk_score)
    if max_risk_score is not None:
        query = query.where(Incident.risk_score <= max_risk_score)
    if start_time:
        query = query.where(Incident.start_time >= start_time)
    if end_time:
        query = query.where(Incident.end_time <= end_time)

    count_query = select(func.count()).select_from(query.subquery())
    total = db.execute(count_query).scalar_one()

    ordered_query = (
        query.order_by(Incident.risk_score.desc(), Incident.start_time.desc())
        .offset(offset)
        .limit(limit)
    )
    items = list(db.execute(ordered_query).scalars().all())
    return total, items


def get_incident_by_id(db: Session, incident_id: str) -> Incident | None:
    """Retrieve full incident details including contributing events and alerts."""
    stmt = (
        select(Incident)
        .options(selectinload(Incident.events), selectinload(Incident.alerts))
        .where(Incident.incident_id == incident_id)
    )
    return db.execute(stmt).scalar_one_or_none()


def update_incident(
    db: Session,
    incident_id: str,
    status: str | None = None,
    description: str | None = None,
) -> Incident | None:
    """Update investigation status or analyst description of an incident."""
    incident = get_incident_by_id(db, incident_id)
    if incident is None:
        return None

    if status is not None:
        incident.status = status.lower()
    if description is not None:
        incident.description = description
    incident.updated_at = utc_now()

    db.commit()
    db.refresh(incident)
    return incident
