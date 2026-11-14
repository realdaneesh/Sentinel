"""Security, Authentication, and RBAC tests for Phase 5."""

from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.database import Base, get_db
from backend.main import app
from backend.models.alert import Alert
from backend.models.incident import Incident
from backend.services.alert_service import create_alert_for_incident
from backend.services.auth_service import create_user


@pytest.fixture
def auth_client_and_db():
    """Create test client with pre-seeded users for admin, analyst, and viewer roles."""
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
        # Create users with different roles
        create_user(session, username="admin_user", password="adminpassword123", role="admin")
        create_user(session, username="analyst_user", password="analystpassword123", role="analyst")
        create_user(session, username="viewer_user", password="viewerpassword123", role="viewer")

        # Create a test incident and alert for RBAC testing
        now = datetime(2026, 11, 14, 12, 0, tzinfo=timezone.utc)
        inc = Incident(
            incident_id="inc-rbac-test",
            title="RBAC Test Incident",
            user_id="victim_alice",
            incident_type="failed_login_burst",
            risk_score=50,
            severity="HIGH",
            status="open",
            start_time=now,
            end_time=now,
        )
        session.add(inc)
        session.commit()
        create_alert_for_incident(session, inc)

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=test_engine)
    test_engine.dispose()


def get_token(client: TestClient, username: str, password: str) -> str:
    """Helper to authenticate and retrieve access token."""
    res = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert res.status_code == 200
    return res.json()["access_token"]


class TestAuthenticationFlow:
    def test_user_registration(self, auth_client_and_db):
        """Test POST /api/v1/auth/register creates user and rejects duplicate username."""
        client = auth_client_and_db

        # 1. Successful registration
        res1 = client.post("/api/v1/auth/register", json={
            "username": "new_analyst",
            "password": "SecurePassword999!",
            "email": "analyst@sentinel.org",
            "role": "analyst",
        })
        assert res1.status_code == 201
        data = res1.json()
        assert data["username"] == "new_analyst"
        assert data["role"] == "analyst"

        # 2. Duplicate username rejection
        res2 = client.post("/api/v1/auth/register", json={
            "username": "new_analyst",
            "password": "AnotherPassword123!",
        })
        assert res2.status_code == 409

    def test_user_login_success_and_failure(self, auth_client_and_db):
        """Test login with valid, wrong password, and nonexistent user."""
        client = auth_client_and_db

        # Valid login
        res_ok = client.post("/api/v1/auth/login", json={
            "username": "admin_user",
            "password": "adminpassword123",
        })
        assert res_ok.status_code == 200
        data = res_ok.json()
        assert "access_token" in data
        assert data["role"] == "admin"

        # Wrong password
        res_bad_pw = client.post("/api/v1/auth/login", json={
            "username": "admin_user",
            "password": "wrongpassword",
        })
        assert res_bad_pw.status_code == 401

        # Nonexistent user
        res_bad_usr = client.post("/api/v1/auth/login", json={
            "username": "ghost_user",
            "password": "somepassword",
        })
        assert res_bad_usr.status_code == 401

    def test_get_current_user_me(self, auth_client_and_db):
        """Test GET /api/v1/auth/me with valid, expired/invalid, and missing tokens."""
        client = auth_client_and_db
        token = get_token(client, "analyst_user", "analystpassword123")

        # Valid token
        res_me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert res_me.status_code == 200
        assert res_me.json()["username"] == "analyst_user"
        assert res_me.json()["role"] == "analyst"

        # Missing token
        res_no_tok = client.get("/api/v1/auth/me")
        assert res_no_tok.status_code == 401

        # Invalid token
        res_invalid = client.get("/api/v1/auth/me", headers={"Authorization": "Bearer invalid.token.value"})
        assert res_invalid.status_code == 401


class TestRoleBasedAccessControl:
    def test_viewer_role_permissions(self, auth_client_and_db):
        """Viewer can view incidents/alerts, but cannot mutate them or view admin user lists."""
        client = auth_client_and_db
        viewer_token = get_token(client, "viewer_user", "viewerpassword123")
        headers = {"Authorization": f"Bearer {viewer_token}"}

        # 1. Can view incidents
        res_inc = client.get("/api/v1/incidents", headers=headers)
        assert res_inc.status_code == 200

        # 2. Can view alerts
        res_alt = client.get("/api/v1/alerts", headers=headers)
        assert res_alt.status_code == 200
        alert_id = res_alt.json()["items"][0]["alert_id"]

        # 3. CANNOT update incident -> 403 Forbidden
        res_patch_inc = client.patch(
            "/api/v1/incidents/inc-rbac-test",
            json={"status": "investigating"},
            headers=headers,
        )
        assert res_patch_inc.status_code == 403

        # 4. CANNOT acknowledge alert -> 403 Forbidden
        res_patch_alt = client.patch(
            f"/api/v1/alerts/{alert_id}",
            json={"is_acknowledged": True},
            headers=headers,
        )
        assert res_patch_alt.status_code == 403

        # 5. CANNOT view admin user list -> 403 Forbidden
        res_users = client.get("/api/v1/auth/users", headers=headers)
        assert res_users.status_code == 403

    def test_analyst_role_permissions(self, auth_client_and_db):
        """Analyst can view and mutate incidents/alerts, but cannot view admin user list."""
        client = auth_client_and_db
        analyst_token = get_token(client, "analyst_user", "analystpassword123")
        headers = {"Authorization": f"Bearer {analyst_token}"}

        # 1. Can update incident -> 200 OK
        res_patch_inc = client.patch(
            "/api/v1/incidents/inc-rbac-test",
            json={"status": "investigating", "description": "Analyst investigating anomaly"},
            headers=headers,
        )
        assert res_patch_inc.status_code == 200
        assert res_patch_inc.json()["status"] == "investigating"

        # 2. Can acknowledge alert -> 200 OK
        alert_id = client.get("/api/v1/alerts", headers=headers).json()["items"][0]["alert_id"]
        res_patch_alt = client.patch(
            f"/api/v1/alerts/{alert_id}",
            json={"is_acknowledged": True, "acknowledged_by": "analyst_user"},
            headers=headers,
        )
        assert res_patch_alt.status_code == 200
        assert res_patch_alt.json()["is_acknowledged"] is True

        # 3. CANNOT view admin user list -> 403 Forbidden
        res_users = client.get("/api/v1/auth/users", headers=headers)
        assert res_users.status_code == 403

    def test_admin_role_permissions(self, auth_client_and_db):
        """Admin has full privileges across all endpoints including user management."""
        client = auth_client_and_db
        admin_token = get_token(client, "admin_user", "adminpassword123")
        headers = {"Authorization": f"Bearer {admin_token}"}

        # 1. Can access user list -> 200 OK
        res_users = client.get("/api/v1/auth/users", headers=headers)
        assert res_users.status_code == 200
        assert len(res_users.json()) >= 3

        # 2. Can update incident -> 200 OK
        res_patch_inc = client.patch(
            "/api/v1/incidents/inc-rbac-test",
            json={"status": "resolved"},
            headers=headers,
        )
        assert res_patch_inc.status_code == 200
        assert res_patch_inc.json()["status"] == "resolved"

    def test_unauthenticated_access_rejected(self, auth_client_and_db):
        """Unauthenticated requests to protected endpoints return 401 Unauthorized."""
        client = auth_client_and_db

        assert client.get("/api/v1/incidents").status_code == 401
        assert client.get("/api/v1/alerts").status_code == 401
        assert client.get("/api/v1/events").status_code == 401
        assert client.patch("/api/v1/incidents/inc-rbac-test", json={"status": "resolved"}).status_code == 401
