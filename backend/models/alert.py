"""Alert persistence model linked to correlated incidents."""

import uuid
from datetime import datetime
from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..database import Base
from .base import utc_now


class Alert(Base):
    __tablename__ = "alerts"

    alert_id: Mapped[str] = mapped_column(
        String(128),
        primary_key=True,
        default=lambda: f"alt-{uuid.uuid4().hex[:16]}",
        index=True,
    )
    incident_id: Mapped[str] = mapped_column(
        String(128),
        ForeignKey("incidents.incident_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    alert_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    severity: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    message: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    is_acknowledged: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        index=True,
    )
    acknowledged_by: Mapped[str | None] = mapped_column(
        String(256),
        nullable=True,
    )
    acknowledged_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
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
    incident = relationship(
        "Incident",
        back_populates="alerts",
    )

    __table_args__ = (
        Index("ix_alerts_severity_ack", "severity", "is_acknowledged"),
    )

    def __repr__(self) -> str:
        return f"<Alert id={self.alert_id!r} type={self.alert_type!r} severity={self.severity!r} ack={self.is_acknowledged}>"

