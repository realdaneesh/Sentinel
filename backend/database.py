"""Database connection management, session factory, and engine lifecycle."""

from collections.abc import Generator
from pathlib import Path
from sqlalchemy import create_engine, event, inspect
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import settings


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy declarative models."""
    pass


# SQLite-specific connect args to allow multithreaded access
connect_args = {}
if settings.DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(
    settings.DATABASE_URL,
    echo=settings.DATABASE_ECHO,
    connect_args=connect_args,
    future=True,
)

# Enable foreign keys for SQLite
if settings.DATABASE_URL.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
)


def get_db() -> Generator[Session, None, None]:
    """Dependency that provides a transactional database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db(engine_instance=None) -> None:
    """Create tables for isolated tests only; never use as a schema upgrade."""
    # Ensure all models are imported before creating tables
    from . import models  # noqa: F401
    target_engine = engine_instance or engine
    Base.metadata.create_all(bind=target_engine)


def require_current_schema(engine_instance=None) -> None:
    """Refuse to start against an unversioned or outdated database."""
    from alembic.runtime.migration import MigrationContext
    from . import models  # noqa: F401

    target_engine = engine_instance or engine
    if target_engine.dialect.name == "sqlite":
        database = target_engine.url.database
        if database and database != ":memory:" and not Path(database).is_file():
            raise RuntimeError("Database does not exist; run reviewed Alembic migrations")
    with target_engine.connect() as connection:
        revision = MigrationContext.configure(connection).get_current_revision()
        if revision != "0003":
            raise RuntimeError("Database schema is not current; run reviewed Alembic migrations")
        inspector = inspect(connection)
        if not set(Base.metadata.tables).issubset(set(inspector.get_table_names())):
            raise RuntimeError("Database schema does not match the recorded revision")
        for name, table in Base.metadata.tables.items():
            columns = {column["name"] for column in inspector.get_columns(name)}
            if columns != set(table.columns.keys()):
                raise RuntimeError("Database schema does not match the recorded revision")
        for name, required, expected_columns in (
            ("incidents", "uq_current_incident_fingerprint",
             ["user_id", "incident_type", "evidence_fingerprint"]),
            ("alerts", "uq_current_alert_type_per_incident", ["incident_id", "alert_type"]),
        ):
            indexes = {index["name"]: index for index in inspector.get_indexes(name)}
            index = indexes.get(required)
            if index is None or not index.get("unique") or index.get("column_names") != expected_columns:
                raise RuntimeError("Database schema does not match the recorded revision")


def drop_db(engine_instance=None) -> None:
    """Drop all tables (useful for tests)."""
    target_engine = engine_instance or engine
    Base.metadata.drop_all(bind=target_engine)

