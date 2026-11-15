"""Original backend tables before Task 008B security and Task 008C reconciliation."""

from alembic import op
import sqlalchemy as sa

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table("users",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("username", sa.String(64), nullable=False, unique=True),
        sa.Column("email", sa.String(255), unique=True),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("role", sa.String(32), nullable=False),
        sa.Column("account_status", sa.String(32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False))
    op.create_index("ix_users_username", "users", ["username"], unique=True)
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    op.create_table("login_events",
        sa.Column("event_id", sa.String(128), primary_key=True),
        sa.Column("user_id", sa.String(256), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_type", sa.String(32), nullable=False),
        sa.Column("source", sa.String(64), nullable=False),
        sa.Column("ip_address", sa.String(45)),
        sa.Column("device_id", sa.String(256)),
        sa.Column("failure_reason", sa.String(256)),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.Column("raw_payload", sa.JSON()),
        sa.Column("detection_status", sa.String(32), nullable=False),
        sa.Column("detection_result", sa.JSON()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    for name, columns in (
        ("ix_login_events_event_id", ["event_id"]),
        ("ix_login_events_user_id", ["user_id"]),
        ("ix_login_events_timestamp", ["timestamp"]),
        ("ix_login_events_ip_address", ["ip_address"]),
        ("ix_login_events_device_id", ["device_id"]),
        ("ix_login_events_user_timestamp", ["user_id", "timestamp"]),
        ("ix_login_events_user_type_timestamp", ["user_id", "event_type", "timestamp"]),
    ):
        op.create_index(name, "login_events", columns)

    op.create_table("incidents",
        sa.Column("incident_id", sa.String(128), primary_key=True),
        sa.Column("title", sa.String(256), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("user_id", sa.String(256), nullable=False),
        sa.Column("incident_type", sa.String(128), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("severity", sa.String(32), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("start_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("end_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("signals", sa.JSON(), nullable=False),
        sa.Column("explanations", sa.JSON(), nullable=False),
        sa.Column("scorer_version", sa.String(32)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False))
    for name, columns in (
        ("ix_incidents_incident_id", ["incident_id"]),
        ("ix_incidents_user_id", ["user_id"]),
        ("ix_incidents_user_id_status", ["user_id", "status"]),
        ("ix_incidents_severity_risk", ["severity", "risk_score"]),
    ):
        op.create_index(name, "incidents", columns)

    op.create_table("incident_events",
        sa.Column("incident_id", sa.String(128), sa.ForeignKey("incidents.incident_id", ondelete="CASCADE"), primary_key=True),
        sa.Column("event_id", sa.String(128), sa.ForeignKey("login_events.event_id", ondelete="CASCADE"), primary_key=True))
    op.create_index("ix_incident_events_incident_id", "incident_events", ["incident_id"])
    op.create_index("ix_incident_events_event_id", "incident_events", ["event_id"])

    op.create_table("alerts",
        sa.Column("alert_id", sa.String(128), primary_key=True),
        sa.Column("incident_id", sa.String(128), sa.ForeignKey("incidents.incident_id", ondelete="CASCADE"), nullable=False),
        sa.Column("alert_type", sa.String(64), nullable=False),
        sa.Column("severity", sa.String(32), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("is_acknowledged", sa.Boolean(), nullable=False),
        sa.Column("acknowledged_by", sa.String(256)),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False))
    for name, columns in (
        ("ix_alerts_alert_id", ["alert_id"]),
        ("ix_alerts_incident_id", ["incident_id"]),
        ("ix_alerts_is_acknowledged", ["is_acknowledged"]),
        ("ix_alerts_severity_ack", ["severity", "is_acknowledged"]),
    ):
        op.create_index(name, "alerts", columns)

    op.create_table("audit_logs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("actor", sa.String(256), nullable=False),
        sa.Column("action", sa.String(128), nullable=False),
        sa.Column("resource_type", sa.String(64), nullable=False),
        sa.Column("resource_id", sa.String(128)),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("details", sa.JSON()))
    for name, columns in (
        ("ix_audit_logs_actor", ["actor"]),
        ("ix_audit_logs_resource_type", ["resource_type"]),
        ("ix_audit_logs_resource_id", ["resource_id"]),
        ("ix_audit_logs_timestamp", ["timestamp"]),
        ("ix_audit_logs_actor_timestamp", ["actor", "timestamp"]),
        ("ix_audit_logs_resource", ["resource_type", "resource_id"]),
    ):
        op.create_index(name, "audit_logs", columns)


def downgrade() -> None:
    raise RuntimeError("Downgrade would delete investigation data")
