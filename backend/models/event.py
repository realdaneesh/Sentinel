"""Login event persistence model conforming to v1 event contract."""

from datetime import datetime
from typing import Any
from sqlalchemy import DateTime, Index, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..database import Base
from .base import utc_now


class LoginEvent(Base):
    __tablename__ = "login_events"

    # Contract specifies stable globally unique opaque string, 1-128 chars
    event_id: Mapped[str] = mapped_column(
        String(128),
        primary_key=True,
        index=True,
    )
    # Exact user_id / identity string, 1-256 chars
    user_id: Mapped[str] = mapped_column(
        String(256),
        index=True,
        nullable=False,
    )
    # Event timestamp (UTC aware)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        index=True,
        nullable=False,
    )
    # LOGIN_SUCCESS or LOGIN_FAILURE
    event_type: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    # Source producer identifier (e.g. sentinel-simulator) or application
    source: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    # Optional IP address (IPv4 or IPv6 literal)
    ip_address: Mapped[str | None] = mapped_column(
        String(45),
        nullable=True,
        index=True,
    )
    # Optional device ID
    device_id: Mapped[str | None] = mapped_column(
        String(256),
        nullable=True,
        index=True,
    )
    # Optional failure reason
    failure_reason: Mapped[str | None] = mapped_column(
        String(256),
        nullable=True,
    )
    # SHA-256 hash of canonical normalized v1 payload for atomic duplicate/conflict checks
    payload_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    # Raw JSON payload stored for audit/replay fidelity
    raw_payload: Mapped[dict[str, Any] | None] = mapped_column(
        JSON,
        nullable=True,
    )
    # Processing status: "pending", "evaluated", "failed"
    detection_status: Mapped[str] = mapped_column(
        String(32),
        default="pending",
        nullable=False,
    )
    # Detection result envelope (stored when evaluated)
    detection_result: Mapped[dict[str, Any] | None] = mapped_column(
        JSON,
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

    # Relationships
    incidents = relationship(
        "Incident",
        secondary="incident_events",
        back_populates="events",
    )

    __table_args__ = (
        Index("ix_login_events_user_timestamp", "user_id", "timestamp"),
        Index("ix_login_events_user_type_timestamp", "user_id", "event_type", "timestamp"),
    )

    def __repr__(self) -> str:
        return f"<LoginEvent event_id={self.event_id!r} user_id={self.user_id!r} type={self.event_type!r}>"

