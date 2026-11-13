"""Service layer for authentication event ingestion, deduplication, and querying."""

from datetime import datetime
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models.event import LoginEvent
from ..schemas.event import EventIngestPayload


class EventConflictError(Exception):
    """Raised when an existing event_id is submitted with different payload content."""
    def __init__(self, event_id: str):
        self.event_id = event_id
        super().__init__(f"event_id already exists with different content: {event_id}")


def ingest_event(db: Session, payload: EventIngestPayload) -> tuple[int, str]:
    """Ingest a validated authentication event atomically.

    Returns:
        (201, "accepted") if newly persisted.
        (200, "duplicate") if an exact identical replay was received.
    Raises:
        EventConflictError (to be mapped to 409 Conflict) if event_id exists with different payload.
    """
    payload_hash = payload.canonical_hash()

    # Query for existing event with this ID
    existing = db.execute(
        select(LoginEvent).where(LoginEvent.event_id == payload.event_id)
    ).scalar_one_or_none()

    if existing is not None:
        if existing.payload_hash == payload_hash:
            return 200, "duplicate"
        else:
            raise EventConflictError(payload.event_id)

    # Persist new event
    new_event = LoginEvent(
        event_id=payload.event_id,
        user_id=payload.user_id,
        timestamp=payload.parsed_datetime(),
        event_type=payload.event_type,
        source=payload.source,
        ip_address=payload.ip_address,
        device_id=payload.device_id,
        failure_reason=payload.failure_reason,
        payload_hash=payload_hash,
        raw_payload=payload.model_dump(),
        detection_status="pending",
    )
    db.add(new_event)
    db.commit()
    db.refresh(new_event)
    return 201, "accepted"


def get_event_by_id(db: Session, event_id: str) -> LoginEvent | None:
    """Retrieve a single login event by ID."""
    return db.execute(
        select(LoginEvent).where(LoginEvent.event_id == event_id)
    ).scalar_one_or_none()


def list_events(
    db: Session,
    user_id: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    event_type: str | None = None,
    ip_address: str | None = None,
    source: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[int, list[LoginEvent]]:
    """List login events with optional filters and pagination."""
    query = select(LoginEvent)

    if user_id:
        query = query.where(LoginEvent.user_id == user_id)
    if start_time:
        query = query.where(LoginEvent.timestamp >= start_time)
    if end_time:
        query = query.where(LoginEvent.timestamp <= end_time)
    if event_type:
        query = query.where(LoginEvent.event_type == event_type)
    if ip_address:
        query = query.where(LoginEvent.ip_address == ip_address)
    if source:
        query = query.where(LoginEvent.source == source)

    # Total count query
    count_query = select(func.count()).select_from(query.subquery())
    total = db.execute(count_query).scalar_one()

    # Paginated ordered query
    ordered_query = query.order_by(LoginEvent.timestamp.desc(), LoginEvent.event_id).offset(offset).limit(limit)
    items = list(db.execute(ordered_query).scalars().all())

    return total, items

