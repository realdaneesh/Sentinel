"""Acquire database-backed locks before reading mutable security state."""

from sqlalchemy import update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from ..models.coordination import AdministratorGuard, IdentityProcessingState


def _insert_if_absent(db: Session, model, values: dict, key: str) -> None:
    dialect = db.get_bind().dialect.name
    if dialect == "sqlite":
        stmt = sqlite_insert(model).values(**values).on_conflict_do_nothing(index_elements=[key])
    elif dialect == "postgresql":
        stmt = pg_insert(model).values(**values).on_conflict_do_nothing(index_elements=[key])
    else:
        raise RuntimeError(f"Unsupported database dialect for coordination: {dialect}")
    db.execute(stmt)


def lock_identity(db: Session, identity: str) -> IdentityProcessingState:
    """Serialize all reconciliation and analyst writes for an exact identity."""
    _insert_if_absent(db, IdentityProcessingState,
                      {"user_id": identity, "lock_version": 0}, "user_id")
    db.execute(update(IdentityProcessingState)
               .where(IdentityProcessingState.user_id == identity)
               .values(lock_version=IdentityProcessingState.lock_version + 1))
    return db.get(IdentityProcessingState, identity, populate_existing=True)


def lock_administrators(db: Session) -> None:
    """Serialize bootstrap and role updates affecting the active-admin invariant."""
    _insert_if_absent(db, AdministratorGuard, {"id": 1, "lock_version": 0}, "id")
    db.execute(update(AdministratorGuard)
               .where(AdministratorGuard.id == 1)
               .values(lock_version=AdministratorGuard.lock_version + 1))
