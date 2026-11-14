"""API tests for Incident Management and Alert APIs conforming to Phase 4."""

from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.database import Base, get_db
from backend.main import app
from backend.models.alert import Alert
from backend.models.event import LoginEvent
from backend.models.incident import Incident
from backend.services.alert_service import create_alert_for_incident


@pytest.fixture
def client_and_db():
    """Create test client with pre-populated incidents, events, and alerts."""
    test_engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    with test_engine.connect() as conn:
        conn.exec_driver_sql("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(bind=test_engine)
    TestingSessionLocal = sessionmaker(bind=test_engine, expire_on_commit=False)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    now = datetime(2026, 11, 14, 10, 0, tzinfo=timezone.utc)
    with TestingSessionLocal() as session:
        # Create events
        e1 = LoginEvent(
            event_id="evt-inc-1",
            user_id="alice_target",
            timestamp=now - timedelta(minutes=10),
            event_type="LOGIN_FAILURE",
            source="portal",
            payload_hash="hash1",
        )
        e2 = LoginEvent(
            event_id="evt-inc-2",
            user_id="alice_target",
            timestamp=now,
            event_type="LOGIN_SUCCESS",
            source="portal",
            ip_address="203.0.113.99",
            payload_hash="hash2",
        )
        session.add_all([e1, e2])

        # Create Incidents
        inc1 = Incident(
            incident_id="inc-alice-high-01",
            title="Failed Login Burst Followed By Unfamiliar IP",
            description="High risk anomaly detected",
            user_id="alice_target",
            incident_type="failed_login_burst_followed_by_unfamiliar_login",
            risk_score=75,
            severity="CRITICAL",
            status="open",
            start_time=now - timedelta(minutes=10),
            end_time=now,
            signals=["failed_login_burst", "unfamiliar_ip", "unfamiliar_device"],
            explanations=["Burst triggered", "Unfamiliar IP address"],
            scorer_version="1.0.0",
        )
        inc1.events.extend([e1, e2])

        inc2 = Incident(
            incident_id="inc-bob-med-02",
            title="Unfamiliar Device Login",
            description="Medium risk login anomaly",
            user_id="bob_normal",
            incident_type="unfamiliar_device",
            risk_score=35,
            severity="MEDIUM",
            status="investigating",
            start_time=now - timedelta(hours=1),
            end_time=now - timedelta(hours=1),
            signals=["unfamiliar_device"],
            explanations=["Unfamiliar device detected"],
            scorer_version="1.0.0",
        )
        session.add_all([inc1, inc2])
        session.commit()

        # Create Alert for inc1
        create_alert_for_incident(session, inc1)

    with TestClient(app) as test_client:
        yield test_client, TestingSessionLocal

    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=test_engine)
    test_engine.dispose()


class TestIncidentManagementAPIs:
    def test_list_incidents_and_filters(self, client_and_db):
        """Test GET /api/v1/incidents with severity, user_id, status, and risk score filters."""
        client, _ = client_and_db

        # 1. List all
        res_all = client.get("/api/v1/incidents")
        assert res_all.status_code == 200
        data = res_all.json()
        assert data["total"] == 2
        assert len(data["items"]) == 2

        # 2. Filter by severity
        res_crit = client.get("/api/v1/incidents?severity=CRITICAL")
        assert res_crit.status_code == 200
        assert res_crit.json()["total"] == 1
        assert res_crit.json()["items"][0]["incident_id"] == "inc-alice-high-01"

        # 3. Filter by user_id
        res_user = client.get("/api/v1/incidents?user_id=bob_normal")
        assert res_user.status_code == 200
        assert res_user.json()["total"] == 1
        assert res_user.json()["items"][0]["user_id"] == "bob_normal"

        # 4. Filter by status
        res_status = client.get("/api/v1/incidents?status=investigating")
        assert res_status.status_code == 200
        assert res_status.json()["total"] == 1
        assert res_status.json()["items"][0]["status"] == "investigating"

        # 5. Filter by min_risk_score
        res_risk = client.get("/api/v1/incidents?min_risk_score=50")
        assert res_risk.status_code == 200
        assert res_risk.json()["total"] == 1
        assert res_risk.json()["items"][0]["risk_score"] == 75

    def test_get_incident_detail_with_contributing_events(self, client_and_db):
        """Test GET /api/v1/incidents/{id} returns traceability to contributing events."""
        client, _ = client_and_db

        res = client.get("/api/v1/incidents/inc-alice-high-01")
        assert res.status_code == 200
        data = res.json()
        assert data["incident_id"] == "inc-alice-high-01"
        assert data["user_id"] == "alice_target"
        assert len(data["events"]) == 2
        event_ids = {e["event_id"] for e in data["events"]}
        assert event_ids == {"evt-inc-1", "evt-inc-2"}

        # 404 for unknown incident
        res_404 = client.get("/api/v1/incidents/inc-nonexistent")
        assert res_404.status_code == 404

    def test_patch_incident_status(self, client_and_db):
        """Test PATCH /api/v1/incidents/{id} updating status and analyst notes."""
        client, _ = client_and_db

        # Update to investigating
        res_inv = client.patch(
            "/api/v1/incidents/inc-alice-high-01",
            json={"status": "investigating", "description": "Analyst investigating IP origin"},
        )
        assert res_inv.status_code == 200
        assert res_inv.json()["status"] == "investigating"
        assert res_inv.json()["description"] == "Analyst investigating IP origin"

        # Update to resolved
        res_res = client.patch(
            "/api/v1/incidents/inc-alice-high-01",
            json={"status": "resolved"},
        )
        assert res_res.status_code == 200
        assert res_res.json()["status"] == "resolved"

        # Invalid status rejection
        res_bad = client.patch(
            "/api/v1/incidents/inc-alice-high-01",
            json={"status": "invalid_status_enum"},
        )
        assert res_bad.status_code == 422


class TestAlertManagementAPIs:
    def test_list_alerts_and_filters(self, client_and_db):
        """Test GET /api/v1/alerts with acknowledgement and severity filters."""
        client, _ = client_and_db

        res = client.get("/api/v1/alerts")
        assert res.status_code == 200
        data = res.json()
        assert data["total"] == 1
        assert data["items"][0]["severity"] == "CRITICAL"
        assert data["items"][0]["is_acknowledged"] is False

        # Filter by is_acknowledged=False
        res_unack = client.get("/api/v1/alerts?is_acknowledged=false")
        assert res_unack.status_code == 200
        assert res_unack.json()["total"] == 1

        # Filter by is_acknowledged=True (currently none)
        res_ack = client.get("/api/v1/alerts?is_acknowledged=true")
        assert res_ack.status_code == 200
        assert res_ack.json()["total"] == 0

    def test_get_alert_detail_with_linked_incident(self, client_and_db):
        """Test GET /api/v1/alerts/{id} retrieves alert and linked incident details."""
        client, _ = client_and_db

        # Get alert_id from list
        alert_id = client.get("/api/v1/alerts").json()["items"][0]["alert_id"]

        res = client.get(f"/api/v1/alerts/{alert_id}")
        assert res.status_code == 200
        data = res.json()
        assert data["alert_id"] == alert_id
        assert data["incident"] is not None
        assert data["incident"]["incident_id"] == "inc-alice-high-01"
        assert data["incident"]["risk_score"] == 75

        # 404 for unknown alert
        res_404 = client.get("/api/v1/alerts/alt-nonexistent")
        assert res_404.status_code == 404

    def test_acknowledge_alert(self, client_and_db):
        """Test PATCH /api/v1/alerts/{id} acknowledging an alert."""
        client, _ = client_and_db
        alert_id = client.get("/api/v1/alerts").json()["items"][0]["alert_id"]

        res = client.patch(
            f"/api/v1/alerts/{alert_id}",
            json={"is_acknowledged": True, "acknowledged_by": "analyst_sarah"},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["is_acknowledged"] is True
        assert data["acknowledged_by"] == "analyst_sarah"
        assert data["acknowledged_at"] is not None

        # Verify alert now shows as acknowledged in list
        res_ack = client.get("/api/v1/alerts?is_acknowledged=true")
        assert res_ack.status_code == 200
        assert res_ack.json()["total"] == 1

    def test_alert_deduplication(self, client_and_db):
        """Verify that calling create_alert_for_incident multiple times does not produce duplicates."""
        _, SessionLocal = client_and_db
        with SessionLocal() as session:
            inc = session.get(Incident, "inc-alice-high-01")
            # Try creating again
            a1 = create_alert_for_incident(session, inc)
            a2 = create_alert_for_incident(session, inc)
            assert a1.alert_id == a2.alert_id
            # Total alerts for this incident remains 1
            from sqlalchemy import select
            alerts = list(session.execute(select(Alert).where(Alert.incident_id == inc.incident_id)).scalars().all())
            assert len(alerts) == 1
