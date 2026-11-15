"""Database rows used to serialize security and detection state changes."""

from datetime import datetime

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


class IdentityProcessingState(Base):
    __tablename__ = "identity_processing_states"

    user_id: Mapped[str] = mapped_column(String(256), primary_key=True)
    evaluated_through: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    lock_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class AdministratorGuard(Base):
    __tablename__ = "administrator_guards"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    lock_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
