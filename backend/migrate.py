"""Validated adoption of the original backend schema into Alembic history."""

import argparse
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect
from sqlalchemy.engine import make_url


ORIGINAL_COLUMNS = {
    "users": {"id", "username", "email", "password_hash", "role", "account_status",
              "created_at", "updated_at"},
    "login_events": {"event_id", "user_id", "timestamp", "event_type", "source",
                     "ip_address", "device_id", "failure_reason", "payload_hash", "raw_payload",
                     "detection_status", "detection_result", "created_at"},
    "incidents": {"incident_id", "title", "description", "user_id", "incident_type",
                  "risk_score", "severity", "status", "start_time", "end_time", "signals",
                  "explanations", "scorer_version", "created_at", "updated_at"},
    "incident_events": {"incident_id", "event_id"},
    "alerts": {"alert_id", "incident_id", "alert_type", "severity", "message",
               "is_acknowledged", "acknowledged_by", "acknowledged_at", "created_at", "updated_at"},
    "audit_logs": {"id", "actor", "action", "resource_type", "resource_id",
                   "timestamp", "details"},
}
ORIGINAL_PRIMARY_KEYS = {
    "users": {"id"}, "login_events": {"event_id"}, "incidents": {"incident_id"},
    "incident_events": {"incident_id", "event_id"}, "alerts": {"alert_id"},
    "audit_logs": {"id"},
}


def config_for(url: str) -> Config:
    config = Config(str(Path(__file__).resolve().parent.parent / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url.replace("%", "%%"))
    return config


def validate_original_schema(url: str) -> None:
    parsed_url = make_url(url)
    if parsed_url.get_backend_name() == "sqlite":
        database = parsed_url.database
        if database and database != ":memory:" and not Path(database).is_file():
            raise ValueError("Original database does not exist")
    engine = create_engine(url)
    try:
        inspector = inspect(engine)
        if set(inspector.get_table_names()) != set(ORIGINAL_COLUMNS):
            raise ValueError("Database is not the original unversioned backend schema")
        for table, expected in ORIGINAL_COLUMNS.items():
            actual = {column["name"] for column in inspector.get_columns(table)}
            primary = set(inspector.get_pk_constraint(table)["constrained_columns"])
            if actual != expected or primary != ORIGINAL_PRIMARY_KEYS[table]:
                raise ValueError(f"Original schema mismatch in {table}")
        user_uniques = {tuple(item["column_names"]) for item in
                        inspector.get_unique_constraints("users")}
        user_uniques.update(tuple(item["column_names"]) for item in
                            inspector.get_indexes("users") if item.get("unique"))
        if not {("username",), ("email",)}.issubset(user_uniques):
            raise ValueError("Original user uniqueness constraints are missing")
        fks = inspector.get_foreign_keys("incident_events")
        if {fk["referred_table"] for fk in fks} != {"incidents", "login_events"}:
            raise ValueError("Original incident evidence foreign keys are missing")
        if {fk["referred_table"] for fk in inspector.get_foreign_keys("alerts")} != {"incidents"}:
            raise ValueError("Original alert foreign key is missing")
        if engine.dialect.name == "sqlite":
            with engine.connect() as connection:
                if connection.exec_driver_sql("PRAGMA foreign_key_check").first() is not None:
                    raise ValueError("Original database contains broken foreign-key references")
    finally:
        engine.dispose()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sentinel database migrations")
    parser.add_argument("operation", choices=["upgrade", "adopt-original"])
    parser.add_argument("--database-url", required=True,
                        help="Explicit URL of an isolated or backed-up database")
    args = parser.parse_args(argv)
    config = config_for(args.database_url)
    if args.operation == "adopt-original":
        validate_original_schema(args.database_url)
        command.stamp(config, "0001")
    command.upgrade(config, "head")
    print("Sentinel database schema is at the latest revision")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
