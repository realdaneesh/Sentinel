"""Incident persistence model and incident-to-event junction table."""

from datetime import datetime
from typing import Any
from sqlalchemy import Column, DateTime, ForeignKey, Index, Integer, JSON, String, Table, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..database import Base
from .base import utc_now


# Junction table linking Incidents and LoginEvents
incident_events = Table(
    "incident_events",
    Base.metadata,
    Column("incident_id", String(128), ForeignKey("incidents.incident_id", ondelete="CASCADE"), primary_key=True),
    Column("event_id", String(128), ForeignKey("login_events.event_id", ondelete="CASCADE"), primary_key=True),
    Index("ix_incident_events_incident_id", "incident_id"),
    Index("ix_incident_events_event_id", "event_id"),
)


class Incident(Base):
    __tablename__ = "incidents"

    incident_id: Mapped[str] = mapped_column(
        String(128),
        primary_key=True,
        index=True,
    )
    title: Mapped[str] = mapped_column(
        String(256),
        nullable=False,
    )
    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    user_id: Mapped[str] = mapped_column(
        String(256),
        index=True,
        nullable=False,
    )
    incident_type: Mapped[str] = mapped_column(
        String(128),
        default="failed_login_burst_followed_by_unfamiliar_login",
        nullable=False,
    )
    risk_score: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )
    severity: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    status: Mapped[str] = mapped_column(
        String(32),
        default="open",
        nullable=False,
    )  # "open", "investigating", "resolved", "false_positive"
    start_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    end_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    signals: Mapped[list[str]] = mapped_column(
        JSON,
        default=list,
        nullable=False,
    )
    explanations: Mapped[list[str]] = mapped_column(
        JSON,
        default=list,
        nullable=False,
    )
    scorer_version: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        nullable=False,
    )

    # Relationships
    events = relationship(
        "LoginEvent",
        secondary=incident_events,
        back_populates="incidents",
    )
    alerts = relationship(
        "Alert",
        back_populates="incident",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        Index("ix_incidents_user_id_status", "user_id", "status"),
        Index("ix_incidents_severity_risk", "severity", "risk_score"),
    )

    def __repr__(self) -> str:
        return f"<Incident id={self.incident_id!r} user={self.user_id!r} score={self.risk_score} severity={self.severity!r}>"
