"""Complete End-to-End System Integration and Scenario Testing for Phase 6."""

from datetime import datetime, timedelta, timezone
import time
from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.database import Base, get_db
from backend.main import app
from backend.models.alert import Alert
from backend.models.audit import AuditLog
from backend.models.event import LoginEvent
from backend.models.incident import Incident
from backend.services.auth_service import create_user


@pytest.fixture
def e2e_client_and_db():
    """Setup isolated in-memory test database with seeded analyst user."""
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

    with TestingSessionLocal() as session:
        # Pre-seed analyst and viewer users
        create_user(session, username="analyst_e2e", password="Password123!", role="analyst")
        create_user(session, username="viewer_e2e", password="Password123!", role="viewer")

    with TestClient(app) as test_client:
        yield test_client, TestingSessionLocal

    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=test_engine)
    test_engine.dispose()


def login_as(client: TestClient, username: str, password: str = "Password123!") -> dict[str, str]:
    """Helper returning Bearer authorization headers."""
    res = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert res.status_code == 200
    token = res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


class TestEndToEndSystemScenarios:
    def test_scenario_1_normal_activity(self, e2e_client_and_db):
        """Scenario 1: Normal login is persisted and evaluated with score 0 and no alerts."""
        client, SessionLocal = e2e_client_and_db
        res = client.post("/api/v1/events", json={
            "schema_version": "1.0",
            "event_id": "evt-e2e-norm-1",
            "user_id": "user_normal",
            "event_type": "LOGIN_SUCCESS",
            "timestamp": "2026-11-14T10:00:00Z",
            "source": "vpn-gateway",
            "ip_address": "192.0.2.10",
            "device_id": "macbook-pro",
        })
        assert res.status_code == 201
        data = res.json()
        assert data["status"] == "accepted"
        assert data["detection_result"]["risk_score"] == 0
        assert data["detection_result"]["severity"] == "LOW"

        # Verify no incident or alert generated
        with SessionLocal() as db:
            incidents = list(db.execute(select(Incident).where(Incident.user_id == "user_normal")).scalars().all())
            assert len(incidents) == 0

    def test_scenario_2_repeated_failed_logins(self, e2e_client_and_db):
        """Scenario 2: Sequence of 5 failed logins triggers burst rule with 35 points."""
        client, _ = e2e_client_and_db
        base_time = datetime(2026, 11, 14, 11, 0, tzinfo=timezone.utc)

        for i in range(5):
            ts = (base_time + timedelta(minutes=i)).isoformat().replace("+00:00", "Z")
            res = client.post("/api/v1/events", json={
                "schema_version": "1.0",
                "event_id": f"evt-e2e-fail-{i}",
                "user_id": "user_brute_target",
                "event_type": "LOGIN_FAILURE",
                "timestamp": ts,
                "source": "web-portal",
            })
            assert res.status_code == 201
            if i == 4:
                # 5th attempt crosses threshold
                det = res.json()["detection_result"]
                assert det["risk_score"] == 35
                assert det["severity"] == "MEDIUM"
                assert any("failed_login_burst: +35 risk points" in r for r in det["reasons"])

    def test_scenario_3_suspicious_novel_login(self, e2e_client_and_db):
        """Scenario 3: Login from unfamiliar IP triggers novelty signal (20 points)."""
        client, _ = e2e_client_and_db
        user = "user_device_check"
        ref = datetime(2026, 11, 14, 12, 0, tzinfo=timezone.utc)

        # Baseline
        client.post("/api/v1/events", json={
            "schema_version": "1.0",
            "event_id": "evt-e2e-base-1",
            "user_id": user,
            "event_type": "LOGIN_SUCCESS",
            "timestamp": (ref - timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
            "source": "portal",
            "ip_address": "192.0.2.1",
        })

        # New IP
        res = client.post("/api/v1/events", json={
            "schema_version": "1.0",
            "event_id": "evt-e2e-novel-ip",
            "user_id": user,
            "event_type": "LOGIN_SUCCESS",
            "timestamp": ref.isoformat().replace("+00:00", "Z"),
            "source": "portal",
            "ip_address": "203.0.113.88",
        })
        assert res.status_code == 201
        det = res.json()["detection_result"]
        assert det["risk_score"] == 20
        assert any("unfamiliar_ip: +20 risk points" in r for r in det["reasons"])

    def test_scenario_4_complete_attack_and_analyst_workflow(self, e2e_client_and_db):
        """Scenario 4: Complete E2E workflow from attack ingestion to analyst investigation and audit logging."""
        client, SessionLocal = e2e_client_and_db
        user = "victim_account"
        ref_time = datetime(2026, 11, 14, 14, 0, tzinfo=timezone.utc)

        # Step 1: Establish baseline
        client.post("/api/v1/events", json={
            "schema_version": "1.0",
            "event_id": "evt-wf-base-0",
            "user_id": user,
            "event_type": "LOGIN_SUCCESS",
            "timestamp": (ref_time - timedelta(minutes=40)).isoformat().replace("+00:00", "Z"),
            "source": "vpn",
            "ip_address": "192.0.2.50",
            "device_id": "work-pc",
        })

        # Step 2: 5 burst failures
        for i in range(5):
            client.post("/api/v1/events", json={
                "schema_version": "1.0",
                "event_id": f"evt-wf-fail-{i}",
                "user_id": user,
                "event_type": "LOGIN_FAILURE",
                "timestamp": (ref_time - timedelta(minutes=10 - i)).isoformat().replace("+00:00", "Z"),
                "source": "vpn",
            })

        # Step 3: Unfamiliar attacker login success
        res_comp = client.post("/api/v1/events", json={
            "schema_version": "1.0",
            "event_id": "evt-wf-comp-success",
            "user_id": user,
            "event_type": "LOGIN_SUCCESS",
            "timestamp": ref_time.isoformat().replace("+00:00", "Z"),
            "source": "vpn",
            "ip_address": "198.51.100.99",
            "device_id": "work-pc",
        })
        assert res_comp.status_code == 201
        assert res_comp.json()["detection_result"]["risk_score"] == 55
        assert res_comp.json()["detection_result"]["severity"] == "HIGH"

        # Step 4: Analyst logs in and retrieves auth token
        analyst_auth = login_as(client, "analyst_e2e", "Password123!")

        # Step 5: Analyst inspects alerts list and finds generated HIGH alert
        res_alerts = client.get("/api/v1/alerts?is_acknowledged=false", headers=analyst_auth)
        assert res_alerts.status_code == 200
        alert_item = res_alerts.json()["items"][0]
        assert alert_item["severity"] == "HIGH"
        alert_id = alert_item["alert_id"]
        incident_id = alert_item["incident_id"]

        # Step 6: Analyst inspects full incident details and contributing event traces
        res_inc = client.get(f"/api/v1/incidents/{incident_id}", headers=analyst_auth)
        assert res_inc.status_code == 200
        inc_data = res_inc.json()
        assert inc_data["risk_score"] == 55
        assert inc_data["status"] == "open"
        assert len(inc_data["events"]) >= 6  # 5 failures + 1 compromise success

        # Step 7: Analyst acknowledges the alert
        res_ack = client.patch(
            f"/api/v1/alerts/{alert_id}",
            json={"is_acknowledged": True},
            headers=analyst_auth,
        )
        assert res_ack.status_code == 200
        assert res_ack.json()["is_acknowledged"] is True
        assert res_ack.json()["acknowledged_by"] == "analyst_e2e"

        # Step 8: Analyst updates incident investigation status to 'investigating', then 'resolved'
        res_inv = client.patch(
            f"/api/v1/incidents/{incident_id}",
            json={"status": "investigating", "description": "Compromised IP identified; session revoked."},
            headers=analyst_auth,
        )
        assert res_inv.status_code == 200
        assert res_inv.json()["status"] == "investigating"

        res_resolved = client.patch(
            f"/api/v1/incidents/{incident_id}",
            json={"status": "resolved"},
            headers=analyst_auth,
        )
        assert res_resolved.status_code == 200
        assert res_resolved.json()["status"] == "resolved"

        # Step 9: Verify audit records were generated for all sensitive analyst actions
        with SessionLocal() as db:
            audit_records = list(db.execute(select(AuditLog).order_by(AuditLog.timestamp.asc())).scalars().all())
            actions = [a.action for a in audit_records]
            assert "ACKNOWLEDGE_ALERT" in actions
            assert "UPDATE_INCIDENT_STATUS" in actions

    def test_scenario_5_api_failures_and_conflict_handling(self, e2e_client_and_db):
        """Scenario 5: Malformed payloads, wrong content-types, and ID conflicts reject cleanly without data loss."""
        client, SessionLocal = e2e_client_and_db

        # 1. Invalid content type
        assert client.post("/api/v1/events", content="test", headers={"Content-Type": "text/plain"}).status_code == 415

        # 2. Malformed JSON
        assert client.post("/api/v1/events", content="{broken_json", headers={"Content-Type": "application/json"}).status_code == 400

        # 3. Missing fields
        assert client.post("/api/v1/events", json={"user_id": "u1"}).status_code == 422

        # 4. Valid event insertion
        valid_event = {
            "schema_version": "1.0",
            "event_id": "evt-e2e-conflict-test",
            "user_id": "user_conflict",
            "event_type": "LOGIN_FAILURE",
            "timestamp": "2026-11-14T15:00:00Z",
            "source": "api",
        }
        assert client.post("/api/v1/events", json=valid_event).status_code == 201

        # 5. Conflicting payload modification
        mod_event = dict(valid_event)
        mod_event["event_type"] = "LOGIN_SUCCESS"
        res_conflict = client.post("/api/v1/events", json=mod_event)
        assert res_conflict.status_code == 409
        assert res_conflict.json()["error"]["code"] == "EVENT_ID_CONFLICT"

        # 6. Verify original event in DB remains unmodified
        with SessionLocal() as db:
            saved = db.get(LoginEvent, "evt-e2e-conflict-test")
            assert saved.event_type == "LOGIN_FAILURE"

    def test_scenario_6_unauthorized_access(self, e2e_client_and_db):
        """Scenario 6: Access control protects sensitive endpoints against unauthenticated and unauthorized roles."""
        client, _ = e2e_client_and_db

        # Unauthenticated
        assert client.get("/api/v1/incidents").status_code == 401
        assert client.get("/api/v1/alerts").status_code == 401
        assert client.get("/api/v1/auth/users").status_code == 401

        # Viewer role (forbidden from admin and mutation)
        viewer_auth = login_as(client, "viewer_e2e", "Password123!")
        assert client.get("/api/v1/auth/users", headers=viewer_auth).status_code == 403
        assert client.patch("/api/v1/incidents/inc-test", json={"status": "resolved"}, headers=viewer_auth).status_code == 403

    def test_performance_rapid_ingestion(self, e2e_client_and_db):
        """Benchmark: Process 30 sequential events and measure throughput and latency."""
        client, _ = e2e_client_and_db
        base_time = datetime(2026, 11, 14, 16, 0, tzinfo=timezone.utc)

        start = time.perf_counter()
        count = 30
        for i in range(count):
            ts = (base_time + timedelta(seconds=i)).isoformat().replace("+00:00", "Z")
            res = client.post("/api/v1/events", json={
                "schema_version": "1.0",
                "event_id": f"evt-perf-{i}",
                "user_id": f"user_perf_{i % 5}",
                "event_type": "LOGIN_FAILURE" if i % 2 == 0 else "LOGIN_SUCCESS",
                "timestamp": ts,
                "source": "perf-tester",
            })
            assert res.status_code == 201

        elapsed = time.perf_counter() - start
        avg_per_event = (elapsed / count) * 1000  # ms
        throughput = count / elapsed

        print(f"\n[PERFORMANCE] {count} events processed in {elapsed:.3f}s: {avg_per_event:.2f}ms/event ({throughput:.1f} events/sec)")
        # Performance assertion: average response time must be under 50ms per event in memory
        assert avg_per_event < 50.0
