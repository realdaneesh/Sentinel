"""Add Task 008B producer security and Task 008C incident reconciliation."""

from alembic import op
import sqlalchemy as sa

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table("event_producers",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("name", sa.String(128), unique=True, nullable=False),
        sa.Column("source", sa.String(64), nullable=False),
        sa.Column("key_hash", sa.String(64), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True)))
    op.add_column("incidents", sa.Column("evidence_fingerprint", sa.String(128)))
    op.add_column("incidents", sa.Column("is_current", sa.Boolean(), nullable=False,
                                         server_default=sa.true()))
    op.add_column("incidents", sa.Column("superseded_by_id", sa.String(128)))
    op.add_column("incidents", sa.Column("split_from_id", sa.String(128)))
    op.add_column("incidents", sa.Column("evidence_history", sa.JSON(), nullable=False,
                                         server_default=sa.text("'[]'")))
    op.create_index("ix_incidents_evidence_fingerprint", "incidents", ["evidence_fingerprint"])
    op.create_index("ix_incidents_is_current", "incidents", ["is_current"])
    op.add_column("alerts", sa.Column("is_current", sa.Boolean(), nullable=False,
                                      server_default=sa.true()))
    op.create_index("ix_alerts_is_current", "alerts", ["is_current"])
    # Legacy IDs were offline fingerprints. Keep every primary key and link intact.
    op.execute("UPDATE incidents SET evidence_fingerprint = incident_id")


def downgrade() -> None:
    raise RuntimeError("Downgrade would discard incident lineage and producer credentials")

