"""Integration tests verifying backend orchestration with Daneesh's detection engine."""

from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.database import Base, get_db
from backend.main import app
from backend.models.alert import Alert
from backend.models.event import LoginEvent
from backend.models.incident import Incident


@pytest.fixture
def client_and_session():
    """Create test client and direct DB session using an in-memory SQLite database."""
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
    with TestClient(app) as test_client:
        yield test_client, TestingSessionLocal

    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=test_engine)
    test_engine.dispose()


class TestDetectionIntegrationWorkflow:
    def test_scenario_a_normal_login(self, client_and_session):
        """Scenario A: A normal successful login is evaluated with risk_score=0 and severity=LOW."""
        client, SessionLocal = client_and_session
        payload = {
            "schema_version": "1.0",
            "event_id": "evt-norm-01",
            "user_id": "alice_normal",
            "event_type": "LOGIN_SUCCESS",
            "timestamp": "2026-11-13T10:00:00Z",
            "source": "web-portal",
            "ip_address": "192.0.2.1",
            "device_id": "laptop-1",
        }
        res = client.post("/api/v1/events", json=payload)
        assert res.status_code == 201
        data = res.json()
        assert data["status"] == "accepted"
        det = data["detection_result"]
        assert det is not None
        assert det["risk_score"] == 0
        assert det["severity"] == "LOW"
        assert det["detector_version"] == "1.0.0"

        # Verify DB status
        with SessionLocal() as db:
            event = db.get(LoginEvent, "evt-norm-01")
            assert event.detection_status == "evaluated"
            assert event.detection_result["risk_score"] == 0

    def test_scenario_b_single_failed_login(self, client_and_session):
        """Scenario B: A single failed login does not cross the burst threshold."""
        client, SessionLocal = client_and_session
        payload = {
            "schema_version": "1.0",
            "event_id": "evt-fail-01",
            "user_id": "bob_single_fail",
            "event_type": "LOGIN_FAILURE",
            "timestamp": "2026-11-13T10:00:00Z",
            "source": "web-portal",
        }
        res = client.post("/api/v1/events", json=payload)
        assert res.status_code == 201
        det = res.json()["detection_result"]
        assert det["risk_score"] == 0
        assert det["severity"] == "LOW"
        assert "threshold of 5 not met" in det["reasons"][0]

    def test_scenario_c_failed_login_burst(self, client_and_session):
        """Scenario C: 5 consecutive failed logins trigger failed_login_burst rule and score 35 points."""
        client, SessionLocal = client_and_session
        base_time = datetime(2026, 11, 13, 11, 0, tzinfo=timezone.utc)

        for i in range(5):
            ts = (base_time + timedelta(minutes=i)).isoformat().replace("+00:00", "Z")
            res = client.post("/api/v1/events", json={
                "schema_version": "1.0",
                "event_id": f"evt-burst-{i}",
                "user_id": "charlie_burst",
                "event_type": "LOGIN_FAILURE",
                "timestamp": ts,
                "source": "api-gateway",
            })
            assert res.status_code == 201
            det = res.json()["detection_result"]

            if i < 4:
                # Attempts 1 to 4: below threshold
                assert det["risk_score"] == 0
                assert det["severity"] == "LOW"
            else:
                # 5th attempt: threshold met!
                assert det["risk_score"] == 35
                assert det["severity"] == "MEDIUM"
                assert any("failed_login_burst: +35 risk points" in r for r in det["reasons"])

    def test_scenario_d_burst_followed_by_unfamiliar_login_correlation(self, client_and_session):
        """Scenario D: Burst of failures followed by unfamiliar login creates a correlated Incident and Alert."""
        client, SessionLocal = client_and_session
        user = "victim_user"
        ref_time = datetime(2026, 11, 13, 14, 0, tzinfo=timezone.utc)

        # 1. Establish baseline success (1 hour earlier)
        client.post("/api/v1/events", json={
            "schema_version": "1.0",
            "event_id": "evt-baseline-0",
            "user_id": user,
            "event_type": "LOGIN_SUCCESS",
            "timestamp": (ref_time - timedelta(minutes=45)).isoformat().replace("+00:00", "Z"),
            "source": "office-vpn",
            "ip_address": "192.0.2.100",
            "device_id": "corporate-laptop-1",
        })

        # 2. Burst of 5 failures
        for i in range(5):
            client.post("/api/v1/events", json={
                "schema_version": "1.0",
                "event_id": f"evt-attack-fail-{i}",
                "user_id": user,
                "event_type": "LOGIN_FAILURE",
                "timestamp": (ref_time - timedelta(minutes=10 - i)).isoformat().replace("+00:00", "Z"),
                "source": "office-vpn",
            })

        # 3. Successful login from an unfamiliar IP (Attacker success)
        res_attacker = client.post("/api/v1/events", json={
            "schema_version": "1.0",
            "event_id": "evt-compromise-success",
            "user_id": user,
            "event_type": "LOGIN_SUCCESS",
            "timestamp": ref_time.isoformat().replace("+00:00", "Z"),
            "source": "office-vpn",
            "ip_address": "198.51.100.200",  # Unfamiliar IP
            "device_id": "corporate-laptop-1",
        })
        assert res_attacker.status_code == 201
        det = res_attacker.json()["detection_result"]
        # Both burst (35) and unfamiliar IP (20) are active in window: total = 55 (HIGH)
        assert det["risk_score"] == 55
        assert det["severity"] == "HIGH"
        assert any("failed_login_burst" in r for r in det["reasons"])
        assert any("unfamiliar_ip" in r for r in det["reasons"])

        # 4. Verify Correlated Incident and Alert created in DB
        with SessionLocal() as db:
            incidents = list(db.execute(select(Incident).where(Incident.user_id == user)).scalars().all())
            assert len(incidents) == 1
            inc = incidents[0]
            assert inc.incident_type == "failed_login_burst_followed_by_unfamiliar_login"
            # Burst (35) + Novel IP (20) = 55 points (HIGH severity)
            assert inc.risk_score == 55
            assert inc.severity == "HIGH"
            assert "failed_login_burst" in inc.signals
            assert "unfamiliar_ip" in inc.signals

            # Verify contributing events linked
            contrib_ids = {e.event_id for e in inc.events}
            assert "evt-compromise-success" in contrib_ids
            assert any(f"evt-attack-fail-" in eid for eid in contrib_ids)

            # Verify automated Alert generation for HIGH severity
            alerts = list(db.execute(select(Alert).where(Alert.incident_id == inc.incident_id)).scalars().all())
            assert len(alerts) == 1
            alert = alerts[0]
            assert alert.severity == "HIGH"
            assert alert.is_acknowledged is False
            assert user in alert.message

    def test_scenario_e_mixed_activity_identity_isolation(self, client_and_session):
        """Scenario E: Failures from User X do not affect the failure count or novelty of User Y."""
        client, SessionLocal = client_and_session
        now = datetime(2026, 11, 13, 16, 0, tzinfo=timezone.utc)

        # 3 failures for User X
        for i in range(3):
            client.post("/api/v1/events", json={
                "schema_version": "1.0",
                "event_id": f"evt-userx-{i}",
                "user_id": "user_x",
                "event_type": "LOGIN_FAILURE",
                "timestamp": (now + timedelta(minutes=i)).isoformat().replace("+00:00", "Z"),
                "source": "portal",
            })

        # 3 failures for User Y
        for i in range(3):
            res_y = client.post("/api/v1/events", json={
                "schema_version": "1.0",
                "event_id": f"evt-usery-{i}",
                "user_id": "user_y",
                "event_type": "LOGIN_FAILURE",
                "timestamp": (now + timedelta(minutes=i)).isoformat().replace("+00:00", "Z"),
                "source": "portal",
            })
            assert res_y.status_code == 201
            # User Y only has 3 failures -> threshold not met
            assert res_y.json()["detection_result"]["risk_score"] == 0
            assert res_y.json()["detection_result"]["severity"] == "LOW"
