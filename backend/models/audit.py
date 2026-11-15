"""Audit log persistence model for security tracking and compliance."""

from datetime import datetime
from typing import Any
from sqlalchemy import DateTime, Index, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base
from .base import utc_now


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )
    actor: Mapped[str] = mapped_column(
        String(256),
        index=True,
        nullable=False,
    )
    action: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )
    resource_type: Mapped[str] = mapped_column(
        String(64),
        index=True,
        nullable=False,
    )  # "event", "incident", "alert", "user", "system"
    resource_id: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
        index=True,
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        index=True,
        nullable=False,
    )
    details: Mapped[dict[str, Any] | None] = mapped_column(
        JSON,
        nullable=True,
    )

    __table_args__ = (
        Index("ix_audit_logs_actor_timestamp", "actor", "timestamp"),
        Index("ix_audit_logs_resource", "resource_type", "resource_id"),
    )

    def __repr__(self) -> str:
        return f"<AuditLog actor={self.actor!r} action={self.action!r} resource={self.resource_type}:{self.resource_id}>"

