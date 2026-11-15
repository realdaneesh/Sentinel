"""Database architecture and persistence tests for Sentinel."""

from datetime import datetime, timezone
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from backend.database import Base
from backend.models import Alert, AuditLog, Incident, LoginEvent, User


@pytest.fixture
def db_session():
    """Create an isolated in-memory SQLite database session for each test."""
    test_engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        future=True,
    )

    # Enable foreign keys on SQLite connection
    with test_engine.connect() as conn:
        conn.exec_driver_sql("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(bind=test_engine)
    TestingSessionLocal = sessionmaker(bind=test_engine, expire_on_commit=False)
    session = TestingSessionLocal()

    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=test_engine)
        test_engine.dispose()


class TestDatabaseFoundation:
    def test_database_connectivity_and_tables(self, db_session):
        """Verify that all core tables are created in the schema."""
        table_names = Base.metadata.tables.keys()
        expected_tables = {
            "users",
            "login_events",
            "incidents",
            "incident_events",
            "alerts",
            "audit_logs",
        }
        assert expected_tables.issubset(table_names)


class TestUserModel:
    def test_create_and_retrieve_user(self, db_session):
        """Test user creation with defaults and successful retrieval."""
        user = User(
            username="security_analyst_1",
            email="analyst1@sentinel.local",
            password_hash="$2b$12$eInsecureHashedPasswordExamplePlaceholder",
            role="analyst",
        )
        db_session.add(user)
        db_session.commit()

        retrieved = db_session.execute(
            select(User).where(User.username == "security_analyst_1")
        ).scalar_one()

        assert retrieved.id.startswith("usr-")
        assert retrieved.username == "security_analyst_1"
        assert retrieved.email == "analyst1@sentinel.local"
        assert retrieved.role == "analyst"
        assert retrieved.account_status == "active"
        assert retrieved.created_at is not None

    def test_user_unique_constraints(self, db_session):
        """Verify unique constraint on username."""
        u1 = User(
            username="duplicate_user",
            password_hash="hash1",
        )
        db_session.add(u1)
        db_session.commit()

        u2 = User(
            username="duplicate_user",
            password_hash="hash2",
        )
        db_session.add(u2)
        with pytest.raises(IntegrityError):
            db_session.commit()


class TestLoginEventModel:
    def test_create_and_retrieve_login_event(self, db_session):
        """Test persisting and querying a login event adhering to v1 event schema."""
        now = datetime.now(timezone.utc)
        event = LoginEvent(
            event_id="evt-test-001",
            user_id="user_alice",
            timestamp=now,
            event_type="LOGIN_FAILURE",
            source="sentinel-simulator",
            ip_address="192.0.2.10",
            device_id="device-laptop-xyz",
            failure_reason="Invalid credentials",
            payload_hash="dummy_sha256_hash_123456",
            raw_payload={"schema_version": "1.0", "event_id": "evt-test-001"},
            detection_status="pending",
        )
        db_session.add(event)
        db_session.commit()

        retrieved = db_session.get(LoginEvent, "evt-test-001")
        assert retrieved is not None
        assert retrieved.user_id == "user_alice"
        assert retrieved.event_type == "LOGIN_FAILURE"
        assert retrieved.ip_address == "192.0.2.10"
        assert retrieved.raw_payload["schema_version"] == "1.0"
        assert retrieved.detection_status == "pending"

    def test_login_event_unique_id_constraint(self, db_session):
        """Verify duplicate event_id raises IntegrityError."""
        now = datetime.now(timezone.utc)
        e1 = LoginEvent(
            event_id="evt-duplicate-id",
            user_id="user_bob",
            timestamp=now,
            event_type="LOGIN_SUCCESS",
            source="portal",
            payload_hash="hash1",
        )
        db_session.add(e1)
        db_session.commit()

        e2 = LoginEvent(
            event_id="evt-duplicate-id",
            user_id="user_bob",
            timestamp=now,
            event_type="LOGIN_SUCCESS",
            source="portal",
            payload_hash="hash2",
        )
        db_session.add(e2)
        with pytest.raises(IntegrityError):
            db_session.commit()


class TestIncidentAndAlertRelationships:
    def test_incident_with_contributing_events_and_alerts(self, db_session):
        """Test incident creation, association with contributing events, and alert generation."""
        now = datetime.now(timezone.utc)

        # Create two contributing login events
        evt1 = LoginEvent(
            event_id="evt-fail-1",
            user_id="target_identity",
            timestamp=now,
            event_type="LOGIN_FAILURE",
            source="test",
            payload_hash="hash_fail_1",
        )
        evt2 = LoginEvent(
            event_id="evt-succ-2",
            user_id="target_identity",
            timestamp=now,
            event_type="LOGIN_SUCCESS",
            source="test",
            ip_address="203.0.113.5",
            payload_hash="hash_succ_2",
        )
        db_session.add_all([evt1, evt2])
        db_session.commit()

        # Create correlated incident
        incident = Incident(
            incident_id="inc-7f8e9d0c1b2a",
            title="Failed Login Burst Followed By Novel IP",
            description="5 failed attempts followed by unfamiliar login",
            user_id="target_identity",
            incident_type="failed_login_burst_followed_by_unfamiliar_login",
            risk_score=55,
            severity="HIGH",
            status="open",
            start_time=now,
            end_time=now,
            signals=["failed_login_burst", "unfamiliar_ip"],
            explanations=["Burst threshold met", "Unseen IP address"],
            scorer_version="1.0.0",
        )
        incident.events.extend([evt1, evt2])
        db_session.add(incident)
        db_session.commit()

        # Create alert linked to incident
        alert = Alert(
            alert_id="alt-001",
            incident_id=incident.incident_id,
            alert_type="HIGH_RISK_AUTHENTICATION",
            severity="HIGH",
            message="Suspicious authentication detected for user target_identity",
        )
        db_session.add(alert)
        db_session.commit()

        # Query incident and verify relationships
        saved_incident = db_session.get(Incident, "inc-7f8e9d0c1b2a")
        assert saved_incident is not None
        assert len(saved_incident.events) == 2
        assert {e.event_id for e in saved_incident.events} == {"evt-fail-1", "evt-succ-2"}
        assert len(saved_incident.alerts) == 1
        assert saved_incident.alerts[0].alert_id == "alt-001"
        assert saved_incident.alerts[0].is_acknowledged is False

        # Test alert acknowledgement
        saved_incident.alerts[0].is_acknowledged = True
        saved_incident.alerts[0].acknowledged_by = "analyst_bob"
        saved_incident.alerts[0].acknowledged_at = now
        db_session.commit()

        updated_alert = db_session.get(Alert, "alt-001")
        assert updated_alert.is_acknowledged is True
        assert updated_alert.acknowledged_by == "analyst_bob"

    def test_incident_deletion_cascades_to_alerts(self, db_session):
        """Verify that deleting an incident cascades to its alerts and clears junction records."""
        now = datetime.now(timezone.utc)
        evt = LoginEvent(
            event_id="evt-cascade-test",
            user_id="user_c",
            timestamp=now,
            event_type="LOGIN_SUCCESS",
            source="test",
            payload_hash="hash_c",
        )
        incident = Incident(
            incident_id="inc-cascade-test",
            title="Test Cascade",
            user_id="user_c",
            risk_score=30,
            severity="MEDIUM",
            start_time=now,
            end_time=now,
        )
        incident.events.append(evt)
        alert = Alert(
            alert_id="alt-cascade-test",
            incident_id=incident.incident_id,
            alert_type="TEST_ALERT",
            severity="MEDIUM",
            message="Cascade test message",
        )
        db_session.add_all([evt, incident, alert])
        db_session.commit()

        # Delete incident
        db_session.delete(incident)
        db_session.commit()

        # Assert alert was cascaded
        assert db_session.get(Alert, "alt-cascade-test") is None
        # Assert underlying login event is preserved
        assert db_session.get(LoginEvent, "evt-cascade-test") is not None


class TestAuditLogModel:
    def test_create_and_query_audit_logs(self, db_session):
        """Test recording audit trail entries for sensitive analyst actions."""
        now = datetime.now(timezone.utc)
        log = AuditLog(
            actor="analyst_alice",
            action="ACKNOWLEDGE_ALERT",
            resource_type="alert",
            resource_id="alt-001",
            timestamp=now,
            details={"comment": "Investigated and verified legitimate employee travel."},
        )
        db_session.add(log)
        db_session.commit()

        retrieved = db_session.execute(
            select(AuditLog).where(AuditLog.actor == "analyst_alice")
        ).scalar_one()

        assert retrieved.id is not None
        assert retrieved.action == "ACKNOWLEDGE_ALERT"
        assert retrieved.resource_type == "alert"
        assert retrieved.details["comment"].startswith("Investigated")

