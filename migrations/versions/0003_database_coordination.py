"""Add database guards and monotonic identity processing watermarks."""

from alembic import op
import sqlalchemy as sa

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table("identity_processing_states",
        sa.Column("user_id", sa.String(256), primary_key=True),
        sa.Column("evaluated_through", sa.DateTime(timezone=True)),
        sa.Column("lock_version", sa.Integer(), nullable=False, server_default="0"))
    op.create_table("administrator_guards",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("lock_version", sa.Integer(), nullable=False, server_default="0"))
    # The original backend did not store evaluation time. The maximum evaluated
    # event timestamp is a conservative lower bound, never an invented later time.
    op.execute("INSERT INTO identity_processing_states (user_id, evaluated_through, lock_version) "
               "SELECT user_id, MAX(timestamp), 0 FROM login_events "
               "WHERE detection_status = 'evaluated' GROUP BY user_id")
    op.execute("INSERT INTO administrator_guards (id, lock_version) VALUES (1, 0)")
    # Original alert creation could repeat after acknowledgement. Preserve all
    # rows, but make only the newest alert in each incident/type current.
    op.execute("UPDATE alerts SET is_current = 0 WHERE alert_id IN ("
               "SELECT alert_id FROM (SELECT alert_id, ROW_NUMBER() OVER ("
               "PARTITION BY incident_id, alert_type ORDER BY created_at DESC, alert_id DESC"
               ") AS rn FROM alerts) ranked WHERE rn > 1)")
    op.create_index("uq_current_alert_type_per_incident", "alerts",
                    ["incident_id", "alert_type"], unique=True,
                    sqlite_where=sa.text("is_current = 1"),
                    postgresql_where=sa.text("is_current = true"))
    op.create_index("uq_current_incident_fingerprint", "incidents",
                    ["user_id", "incident_type", "evidence_fingerprint"], unique=True,
                    sqlite_where=sa.text("is_current = 1 AND evidence_fingerprint IS NOT NULL"),
                    postgresql_where=sa.text("is_current = true AND evidence_fingerprint IS NOT NULL"))


def downgrade() -> None:
    raise RuntimeError("Downgrade would discard processing coordination history")
