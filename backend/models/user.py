"""User model for authentication, authorization, and audit attribution."""

import uuid
from datetime import datetime
from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base
from .base import utc_now


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: f"usr-{uuid.uuid4().hex[:16]}",
    )
    username: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        index=True,
        nullable=False,
    )
    email: Mapped[str | None] = mapped_column(
        String(255),
        unique=True,
        index=True,
        nullable=True,
    )
    password_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    role: Mapped[str] = mapped_column(
        String(32),
        default="viewer",
        nullable=False,
    )  # "admin", "analyst", "viewer"
    account_status: Mapped[str] = mapped_column(
        String(32),
        default="active",
        nullable=False,
    )  # "active", "suspended", "disabled"
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

    def __repr__(self) -> str:
        return f"<User username={self.username!r} role={self.role!r} status={self.account_status!r}>"

