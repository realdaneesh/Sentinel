"""Security regressions for local administrators, JWTs, and event producers."""

from datetime import datetime, timedelta, timezone
import os
import subprocess
import sys

import jwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.pool import StaticPool

from backend.config import Settings, settings
from backend.api.v1.auth import update_user_role
from backend.database import Base, get_db
from backend.main import app
from backend.models.alert import Alert
from backend.models.audit import AuditLog
from backend.models.event import LoginEvent
from backend.models.incident import Incident
from backend.models.producer import EventProducer
from backend.models.user import User
from backend.schemas.auth import UserRoleUpdate
from backend.services.auth_service import create_user
from backend.services.producer_service import (
    provision_producer, revoke_producer, rotate_producer,
)


@pytest.fixture
def secured_client():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)

    def override_get_db():
        with SessionLocal() as db:
            yield db

    app.dependency_overrides[get_db] = override_get_db
    with SessionLocal() as db:
        admin = create_user(db, username="security_admin", password="SyntheticPassword123!", role="admin")
        analyst = create_user(db, username="security_analyst", password="SyntheticPassword123!", role="analyst")
        viewer = create_user(db, username="security_viewer", password="SyntheticPassword123!", role="viewer")
        producer, key = provision_producer(db, name="synthetic-agent", source="synthetic-agent")
    with TestClient(app) as client:
        yield client, SessionLocal, {"admin": admin, "analyst": analyst, "viewer": viewer}, producer, key
    app.dependency_overrides.clear()
    engine.dispose()


def _jwt_headers(client, username):
    response = client.post("/api/v1/auth/login", json={
        "username": username, "password": "SyntheticPassword123!",
    })
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def _event(event_id="evt-security-1", source="synthetic-agent"):
    return {"schema_version": "1.0", "event_id": event_id, "user_id": "synthetic-target",
            "event_type": "LOGIN_FAILURE", "timestamp": "2026-11-14T12:00:00Z", "source": source}


def test_public_registration_is_viewer_only_and_never_exposes_hash(secured_client):
    client, _, _, _, _ = secured_client
    accepted = client.post("/api/v1/auth/register", json={
        "username": "new_viewer", "password": "SyntheticPassword123!"})
    assert accepted.status_code == 201
    assert accepted.json()["role"] == "viewer"
    assert "password_hash" not in accepted.json()
    for role in ("admin", "analyst"):
        denied = client.post("/api/v1/auth/register", json={
            "username": f"want_{role}", "password": "SyntheticPassword123!", "role": role})
        assert denied.status_code == 422
    assert client.post("/api/v1/auth/register", data={
        "username": "form_admin", "password": "SyntheticPassword123!", "role": "admin",
    }).status_code == 422
    assert client.post("/api/v1/auth/register", json={
        "username": "null_role", "password": "SyntheticPassword123!", "role": None,
    }).status_code == 422


def test_local_admin_bootstrap_prompts_and_refuses_second_admin(monkeypatch, capsys):
    from backend import manage

    engine = create_engine("sqlite:///:memory:", poolclass=StaticPool)
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
    monkeypatch.setattr(manage, "SessionLocal", SessionLocal)
    monkeypatch.setattr(manage, "init_db", lambda: None)
    prompts = iter(["SyntheticAdminPassword123!", "SyntheticAdminPassword123!"])
    monkeypatch.setattr(manage.getpass, "getpass", lambda _: next(prompts))
    assert manage.main(["bootstrap-admin", "--username", "first_admin"]) == 0
    assert "SyntheticAdminPassword123!" not in capsys.readouterr().out
    with SessionLocal() as db:
        user = db.execute(select(User).where(User.username == "first_admin")).scalar_one()
        assert user.role == "admin"
        assert user.password_hash != "SyntheticAdminPassword123!"
        assert db.execute(select(AuditLog).where(AuditLog.action == "BOOTSTRAP_ADMIN")).scalar_one()
    with pytest.raises(SystemExit):
        manage.main(["bootstrap-admin", "--username", "second_admin"])
    engine.dispose()


def test_admin_role_management_last_admin_and_audit(secured_client):
    client, SessionLocal, users, _, _ = secured_client
    endpoint = f"/api/v1/auth/users/{users['viewer'].id}/role"
    for role in ("viewer", "analyst"):
        denied = client.patch(endpoint, json={"role": "analyst"},
                              headers=_jwt_headers(client, f"security_{role}"))
        assert denied.status_code == 403
    admin_headers = _jwt_headers(client, "security_admin")
    changed = client.patch(endpoint, json={"role": "analyst"}, headers=admin_headers)
    assert changed.status_code == 200
    assert changed.json()["role"] == "analyst"
    assert "password_hash" not in changed.json()
    final_admin = client.patch(f"/api/v1/auth/users/{users['admin'].id}/role",
                               json={"role": "viewer"}, headers=admin_headers)
    assert final_admin.status_code == 409
    with SessionLocal() as db:
        audit = db.execute(select(AuditLog).where(AuditLog.action == "CHANGE_USER_ROLE")).scalar_one()
        assert audit.resource_id == users["viewer"].id
        assert audit.details == {"old_role": "viewer", "new_role": "analyst"}
        assert db.get(User, users["admin"].id).role == "admin"


def test_role_and_audit_share_one_commit(secured_client):
    _, SessionLocal, users, _, _ = secured_client
    with SessionLocal() as db:
        admin = db.get(User, users["admin"].id)
        target = db.get(User, users["viewer"].id)

        def fail_audit(session, flush_context, instances):
            if any(isinstance(item, AuditLog) for item in session.new):
                raise RuntimeError("synthetic audit write failure")

        event.listen(db, "before_flush", fail_audit)
        with pytest.raises(RuntimeError, match="synthetic audit write failure"):
            update_user_role(target.id, UserRoleUpdate(role="analyst"), admin, db)
        db.rollback()
    with SessionLocal() as db:
        assert db.get(User, users["viewer"].id).role == "viewer"
        assert db.execute(select(AuditLog).where(AuditLog.action == "CHANGE_USER_ROLE")).first() is None


@pytest.mark.parametrize("kind", ["incident", "alert"])
def test_analyst_update_rolls_back_when_audit_write_fails(secured_client, monkeypatch, kind):
    client, SessionLocal, _, _, _ = secured_client
    now = datetime(2026, 11, 14, 12, tzinfo=timezone.utc)
    with SessionLocal() as db:
        incident = Incident(incident_id="inc-audit-failure", user_id="synthetic-target",
                            title="Synthetic incident", incident_type="failed_login_burst_followed_by_unfamiliar_login",
                            risk_score=75, severity="CRITICAL", status="open", start_time=now,
                            end_time=now, signals=["failed_login_burst"], explanations=["synthetic"])
        alert = Alert(alert_id="alt-audit-failure", incident=incident,
                      alert_type="THREAT_INCIDENT_CORRELATED", severity="CRITICAL",
                      message="Synthetic alert", is_acknowledged=False)
        db.add_all([incident, alert])
        db.commit()

    def fail_audit(*args, **kwargs):
        raise SQLAlchemyError("synthetic audit storage failure")

    if kind == "incident":
        from backend.api.v1 import incidents as route
        monkeypatch.setattr(route, "record_audit_log", fail_audit)
        response = client.patch("/api/v1/incidents/inc-audit-failure",
                                json={"status": "investigating", "description": "Synthetic analyst note"},
                                headers=_jwt_headers(client, "security_analyst"))
    else:
        from backend.api.v1 import alerts as route
        monkeypatch.setattr(route, "record_audit_log", fail_audit)
        response = client.patch("/api/v1/alerts/alt-audit-failure",
                                json={"is_acknowledged": True},
                                headers=_jwt_headers(client, "security_analyst"))
    assert response.status_code == 503
    assert "synthetic audit storage failure" not in response.text
    with SessionLocal() as db:
        assert db.get(Incident, "inc-audit-failure").status == "open"
        assert db.get(Incident, "inc-audit-failure").description is None
        assert db.get(Alert, "alt-audit-failure").is_acknowledged is False
        assert db.scalar(select(AuditLog).where(AuditLog.resource_id == "inc-audit-failure")) is None


def test_old_jwt_uses_current_database_role_and_inactive_state(secured_client):
    client, SessionLocal, users, _, _ = secured_client
    viewer_headers = _jwt_headers(client, "security_viewer")
    admin_headers = _jwt_headers(client, "security_admin")
    assert client.get("/api/v1/auth/users", headers=viewer_headers).status_code == 403
    assert client.patch(f"/api/v1/auth/users/{users['viewer'].id}/role", json={"role": "admin"},
                        headers=admin_headers).status_code == 200
    assert client.get("/api/v1/auth/users", headers=viewer_headers).status_code == 200
    assert client.patch(f"/api/v1/auth/users/{users['admin'].id}/role", json={"role": "viewer"},
                        headers=viewer_headers).status_code == 200
    assert client.get("/api/v1/auth/users", headers=admin_headers).status_code == 403
    with SessionLocal() as db:
        user = db.get(User, users["viewer"].id)
        user.account_status = "disabled"
        db.commit()
    assert client.get("/api/v1/auth/users", headers=viewer_headers).status_code == 403


def test_missing_invalid_expired_and_wrongly_signed_jwts(secured_client):
    client, _, _, _, _ = secured_client
    endpoint = "/api/v1/auth/me"
    assert client.get(endpoint).status_code == 401
    assert client.get(endpoint, headers={"Authorization": "Bearer invalid"}).status_code == 401
    past = datetime.now(timezone.utc) - timedelta(hours=1)
    expired = jwt.encode({"sub": "security_admin", "exp": past}, settings.SECRET_KEY, algorithm="HS256")
    assert client.get(endpoint, headers={"Authorization": f"Bearer {expired}"}).status_code == 401
    wrong = jwt.encode({"sub": "security_admin", "exp": past + timedelta(days=2)},
                       "another-synthetic-signing-key-with-sufficient-length-2026", algorithm="HS256")
    assert client.get(endpoint, headers={"Authorization": f"Bearer {wrong}"}).status_code == 401
    no_exp = jwt.encode({"sub": "security_admin", "iat": datetime.now(timezone.utc)},
                        settings.SECRET_KEY, algorithm="HS256")
    assert client.get(endpoint, headers={"Authorization": f"Bearer {no_exp}"}).status_code == 401


def test_signing_configuration_rejects_missing_weak_and_wrong_algorithm(monkeypatch):
    monkeypatch.delenv("SECRET_KEY", raising=False)
    for value in (None, "short", "sentinel-insecure-development-secret-key-change-me-32chars",
                  "CHANGE_THIS_IN_PRODUCTION_TO_A_SECURE_RANDOM_SECRET_KEY",
                  "REPLACE_WITH_A_RANDOMLY_GENERATED_SIGNING_SECRET",
                  "generate-a-secure-random-key-for-production",
                  "test-only-example-with-adequate-length-and-variation"):
        kwargs = {"ENVIRONMENT": "production"}
        if value is not None:
            kwargs["SECRET_KEY"] = value
        with pytest.raises((ValueError, RuntimeError)):
            Settings(_env_file=None, **kwargs)
    with pytest.raises(RuntimeError):
        Settings(_env_file=None, ENVIRONMENT="development",
                 SECRET_KEY="REPLACE_WITH_A_RANDOMLY_GENERATED_SIGNING_SECRET")
    with pytest.raises(ValueError):
        Settings(_env_file=None, SECRET_KEY="valid-synthetic-secret-of-sufficient-length-2026", ALGORITHM="none")


def test_rejected_signing_secret_is_not_echoed_on_startup():
    placeholder = "REPLACE_WITH_A_RANDOMLY_GENERATED_SIGNING_SECRET"
    environment = os.environ.copy()
    environment["SECRET_KEY"] = placeholder
    result = subprocess.run(
        [sys.executable, "-c", "from backend.config import settings"],
        capture_output=True, text=True, env=environment, check=False,
    )
    assert result.returncode != 0
    assert placeholder not in result.stderr
    assert "SECRET_KEY must be an explicit strong signing secret" in result.stderr


def test_producer_keys_are_hashed_rotated_revoked_and_source_bound(secured_client):
    client, SessionLocal, _, producer, key = secured_client
    headers = {"X-Sentinel-Producer-Key": key}
    with SessionLocal() as db:
        stored = db.get(EventProducer, producer.id)
        assert key not in stored.key_hash
        assert len(stored.key_hash) == 64
    for route in ("/events", "/api/v1/events", "/api/v1/events/login"):
        assert client.post(route, json=_event()).status_code == 401
        assert client.post(route, json=_event(), headers={"X-Sentinel-Producer-Key": "invalid"}).status_code == 401
    with SessionLocal() as db:
        assert db.get(LoginEvent, "evt-security-1") is None
        assert db.scalar(select(Incident)) is None
        assert db.scalar(select(Alert)) is None
    assert client.post("/api/v1/events", json=_event(source="other-agent"), headers=headers).status_code == 403
    accepted = client.post("/events", json=_event(), headers=headers)
    assert accepted.status_code == 201
    assert "key_hash" not in accepted.text
    assert "password_hash" not in accepted.text
    assert client.post("/api/v1/events", json=_event(), headers=headers).status_code == 200
    assert client.post("/api/v1/events/login", json={**_event(), "event_type": "LOGIN_SUCCESS"},
                       headers=headers).status_code == 409
    with SessionLocal() as db:
        _, replacement = rotate_producer(db, producer.id)
    assert client.post("/api/v1/events", json=_event("evt-rotated"), headers=headers).status_code == 401
    new_headers = {"X-Sentinel-Producer-Key": replacement}
    assert client.post("/api/v1/events", json=_event("evt-rotated"), headers=new_headers).status_code == 201
    with SessionLocal() as db:
        revoke_producer(db, producer.id)
    assert client.post("/api/v1/events", json=_event("evt-revoked"), headers=new_headers).status_code == 401
    with SessionLocal() as db:
        assert db.get(LoginEvent, "evt-revoked") is None
        assert db.scalar(select(Incident)) is None
        assert db.scalar(select(Alert)) is None


def test_normalized_convenience_source_and_credential_separation(secured_client):
    client, SessionLocal, _, _, key = secured_client
    jwt_headers = _jwt_headers(client, "security_admin")
    producer_headers = {"X-Sentinel-Producer-Key": key}
    assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {key}"}).status_code == 401
    assert client.post("/api/v1/events", json=_event("evt-jwt-only"), headers=jwt_headers).status_code == 401
    assert client.post("/api/v1/events", json=_event("evt-jwt-as-key"),
                       headers={"X-Sentinel-Producer-Key": jwt_headers["Authorization"].split()[1]}).status_code == 401
    convenience = {"event_id": "evt-convenience-source", "user_id": "synthetic-target",
                   "timestamp": "2026-11-14T12:01:00Z", "status": "failed",
                   "application": "synthetic-agent"}
    assert client.post("/api/v1/events/login", json=convenience, headers=producer_headers).status_code == 201
    mismatched = {**convenience, "event_id": "evt-convenience-denied", "application": "other-agent"}
    assert client.post("/api/v1/events/login", json=mismatched, headers=producer_headers).status_code == 403
    with SessionLocal() as db:
        assert db.get(LoginEvent, "evt-convenience-denied") is None
        assert db.get(LoginEvent, "evt-jwt-only") is None
        assert db.get(LoginEvent, "evt-jwt-as-key") is None


def test_simulator_requires_admin_and_explicit_nonproduction_enablement(secured_client, monkeypatch):
    client, SessionLocal, _, _, _ = secured_client
    request = {"scenario": "normal_activity", "seed": 2, "count": 2, "ingest": True}
    assert client.post("/api/v1/simulator/generate", json=request).status_code == 401
    assert client.post("/api/v1/simulator/generate", json=request,
                       headers=_jwt_headers(client, "security_viewer")).status_code == 403
    assert client.post("/api/v1/simulator/generate", json=request,
                       headers=_jwt_headers(client, "security_analyst")).status_code == 403
    admin_headers = _jwt_headers(client, "security_admin")
    accepted = client.post("/api/v1/simulator/generate", json=request, headers=admin_headers)
    assert accepted.status_code == 200 and accepted.json()["ingested"] is True
    monkeypatch.setattr(settings, "ENVIRONMENT", "development")
    assert client.post("/api/v1/simulator/generate", json={**request, "seed": 3},
                       headers=admin_headers).status_code == 200
    monkeypatch.setattr(settings, "SIMULATOR_PERSISTENCE_ENABLED", False)
    assert client.post("/api/v1/simulator/generate", json=request, headers=admin_headers).status_code == 403
    monkeypatch.setattr(settings, "SIMULATOR_PERSISTENCE_ENABLED", True)
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    assert client.post("/api/v1/simulator/generate", json=request, headers=admin_headers).status_code == 403
    assert client.post("/api/v1/simulator/generate", json={**request, "ingest": False},
                       headers=admin_headers).status_code == 200
    with SessionLocal() as db:
        assert db.scalar(select(LoginEvent).where(LoginEvent.source == "sentinel-simulator")) is not None
