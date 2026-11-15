"""Isolated SQLite migration, replay, and recovery checks for Task 008D."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from threading import Barrier

import pytest
from alembic import command
from alembic.runtime.migration import MigrationContext
from sqlalchemy import create_engine, event as sa_event, inspect, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker

from backend.database import Base, require_current_schema
from backend.migrate import config_for, main as migrate_main, validate_original_schema
from backend.models import Alert, AuditLog, Incident, LoginEvent, User
from backend.models.coordination import IdentityProcessingState
from backend.schemas.event import EventIngestPayload
from backend.services.detection_adapter import reconcile_identity
from backend.services.event_service import EventConflictError, StorageUnavailableError, ingest_event
from backend.services.auth_service import create_user
from backend.api.v1.auth import update_user_role
from backend.schemas.auth import UserRoleUpdate
from backend.schemas.incident import IncidentUpdate
from backend.api.v1.incidents import patch_incident
from backend import manage
from fastapi import HTTPException
from fastapi.testclient import TestClient
from backend.main import app


BASE = datetime(2026, 11, 14, 12, tzinfo=timezone.utc)


def payload(event_id="same-id", *, user_id="synthetic-user", device="known"):
    return EventIngestPayload.model_validate({
        "schema_version": "1.0", "event_id": event_id, "user_id": user_id,
        "event_type": "LOGIN_SUCCESS", "timestamp": BASE.isoformat().replace("+00:00", "Z"),
        "source": "synthetic-producer", "device_id": device,
    })


def auth_event(event_id, kind, minute, *, device=None, ip=None, identity="synthetic-user"):
    body = {"schema_version": "1.0", "event_id": event_id, "user_id": identity,
            "event_type": kind, "timestamp": (BASE + timedelta(minutes=minute)).isoformat().replace("+00:00", "Z"),
            "source": "synthetic-producer"}
    if device is not None:
        body["device_id"] = device
    if ip is not None:
        body["ip_address"] = ip
    return EventIngestPayload.model_validate(body)


def seed_burst(SessionLocal):
    with SessionLocal() as db:
        ingest_event(db, auth_event("baseline", "LOGIN_SUCCESS", -120,
                                    device="known", ip="192.0.2.1"),
                     evaluation_time=BASE + timedelta(minutes=10))
        for index in range(5):
            ingest_event(db, auth_event(f"failure-{index}", "LOGIN_FAILURE", index),
                         evaluation_time=BASE + timedelta(minutes=10))


def test_fresh_migration_tracks_revision_and_matches_models(tmp_path):
    url = f"sqlite:///{(tmp_path / 'fresh.db').as_posix()}"
    command.upgrade(config_for(url), "head")
    engine = create_engine(url)
    require_current_schema(engine)
    with engine.connect() as connection:
        assert MigrationContext.configure(connection).get_current_revision() == "0003"
    inspector = inspect(engine)
    assert set(Base.metadata.tables).issubset(set(inspector.get_table_names()))
    for name, table in Base.metadata.tables.items():
        assert set(table.columns.keys()) == {column["name"] for column in inspector.get_columns(name)}
    engine.dispose()


def test_testing_startup_does_not_initialize_default_database(monkeypatch):
    from backend import main

    def forbidden():
        raise AssertionError("testing startup touched the default database")

    monkeypatch.setattr(main, "require_current_schema", forbidden)
    with TestClient(app) as client:
        assert client.get("/health").status_code == 200


def test_validated_original_migration_preserves_investigation_data(tmp_path):
    url = f"sqlite:///{(tmp_path / 'original.db').as_posix()}"
    command.upgrade(config_for(url), "0001")
    engine = create_engine(url)
    stamp = "2026-11-14 12:00:00"
    with engine.begin() as connection:
        connection.execute(text("INSERT INTO users (id,username,password_hash,role,account_status,created_at,updated_at) "
                                "VALUES ('usr-legacy','legacy-analyst','synthetic-hash','analyst','active',:t,:t)"), {"t": stamp})
        connection.execute(text("INSERT INTO login_events (event_id,user_id,timestamp,event_type,source,payload_hash,detection_status,created_at) "
                                "VALUES ('evt-legacy','legacy-id',:t,'LOGIN_FAILURE','synthetic-producer','hash','evaluated',:t)"), {"t": stamp})
        connection.execute(text("INSERT INTO incidents (incident_id,title,description,user_id,incident_type,risk_score,severity,status,start_time,end_time,signals,explanations,created_at,updated_at) "
                                "VALUES ('inc-legacy','Legacy','Analyst note','legacy-id','failed_login_burst_followed_by_unfamiliar_login',75,'CRITICAL','investigating',:t,:t,'[]','[]',:t,:t)"), {"t": stamp})
        connection.execute(text("INSERT INTO incident_events (incident_id,event_id) VALUES ('inc-legacy','evt-legacy')"))
        connection.execute(text("INSERT INTO alerts (alert_id,incident_id,alert_type,severity,message,is_acknowledged,acknowledged_by,created_at,updated_at) "
                                "VALUES ('alt-legacy','inc-legacy','THREAT','CRITICAL','Synthetic alert',1,'legacy-analyst',:t,:t)"), {"t": stamp})
        connection.execute(text("INSERT INTO alerts (alert_id,incident_id,alert_type,severity,message,is_acknowledged,created_at,updated_at) "
                                "VALUES ('alt-legacy-2','inc-legacy','THREAT','CRITICAL','Newer synthetic alert',0,:t,:t)"), {"t": stamp})
        connection.execute(text("INSERT INTO audit_logs (actor,action,resource_type,resource_id,timestamp) "
                                "VALUES ('legacy-analyst','UPDATE_INCIDENT_STATUS','incident','inc-legacy',:t)"), {"t": stamp})
        connection.execute(text("DROP TABLE alembic_version"))
    validate_original_schema(url)
    assert migrate_main(["adopt-original", "--database-url", url]) == 0
    with sessionmaker(bind=engine)() as db:
        assert db.get(User, "usr-legacy").role == "analyst"
        assert db.get(LoginEvent, "evt-legacy").detection_status == "evaluated"
        incident = db.get(Incident, "inc-legacy")
        assert incident.status == "investigating" and incident.description == "Analyst note"
        assert incident.evidence_fingerprint == "inc-legacy" and incident.is_current
        assert incident.evidence_history == []
        assert {event.event_id for event in incident.events} == {"evt-legacy"}
        alert = db.get(Alert, "alt-legacy")
        assert alert.is_acknowledged and alert.acknowledged_by == "legacy-analyst" and not alert.is_current
        assert db.get(Alert, "alt-legacy-2").is_current
        assert db.scalar(select(AuditLog).where(AuditLog.resource_id == "inc-legacy"))
        assert db.get(IdentityProcessingState, "legacy-id").evaluated_through is not None
    with engine.connect() as connection:
        assert MigrationContext.configure(connection).get_current_revision() == "0003"
    engine.dispose()


def test_unrecognized_schema_cannot_be_stamped(tmp_path):
    url = f"sqlite:///{(tmp_path / 'unrecognized.db').as_posix()}"
    engine = create_engine(url)
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE users (id VARCHAR PRIMARY KEY)"))
    with pytest.raises(ValueError, match="not the original"):
        migrate_main(["adopt-original", "--database-url", url])
    with pytest.raises(RuntimeError, match="not current"):
        require_current_schema(engine)
    assert "alembic_version" not in inspect(engine).get_table_names()
    engine.dispose()


def test_missing_sqlite_database_is_not_created_by_startup_or_adoption(tmp_path):
    database = tmp_path / "missing.db"
    url = f"sqlite:///{database.as_posix()}"
    engine = create_engine(url)
    with pytest.raises(RuntimeError, match="does not exist"):
        require_current_schema(engine)
    assert not database.exists()
    with pytest.raises(ValueError, match="does not exist"):
        migrate_main(["adopt-original", "--database-url", url])
    assert not database.exists()
    engine.dispose()


def test_stamped_but_incomplete_schema_is_rejected(tmp_path):
    url = f"sqlite:///{(tmp_path / 'false-stamp.db').as_posix()}"
    engine = create_engine(url)
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE alembic_version (version_num VARCHAR(32) PRIMARY KEY)"))
        connection.execute(text("INSERT INTO alembic_version (version_num) VALUES ('0003')"))
    with pytest.raises(RuntimeError, match="does not match"):
        require_current_schema(engine)
    engine.dispose()


def test_missing_current_uniqueness_index_is_rejected(tmp_path):
    url = f"sqlite:///{(tmp_path / 'missing-index.db').as_posix()}"
    command.upgrade(config_for(url), "head")
    engine = create_engine(url)
    with engine.begin() as connection:
        connection.execute(text("DROP INDEX uq_current_alert_type_per_incident"))
    with pytest.raises(RuntimeError, match="does not match"):
        require_current_schema(engine)
    engine.dispose()


@pytest.mark.parametrize("conflicting", [False, True])
def test_concurrent_replay_uses_single_event_row(tmp_path, conflicting):
    engine = create_engine(f"sqlite:///{(tmp_path / 'race.db').as_posix()}",
                           connect_args={"check_same_thread": False, "timeout": 30})
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
    barrier = Barrier(2)

    def submit(device):
        with SessionLocal() as db:
            barrier.wait()
            try:
                return ingest_event(db, payload(device=device), run_detection=False)[:2]
            except EventConflictError:
                return "conflict"

    with ThreadPoolExecutor(max_workers=2) as workers:
        results = list(workers.map(submit, ["known", "new" if conflicting else "known"]))
    with SessionLocal() as db:
        rows = list(db.scalars(select(LoginEvent)).all())
        assert len(rows) == 1
        assert db.scalars(select(Incident)).all() == []
        assert db.scalars(select(Alert)).all() == []
        if conflicting:
            assert sorted(str(item) for item in results) == sorted(["conflict", "(201, 'accepted')"])
            assert rows[0].device_id in ("known", "new")
        else:
            assert sorted(results) == [(200, "duplicate"), (201, "accepted")]
    engine.dispose()


def test_detection_failure_keeps_accepted_event_and_retry_recovers(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{(tmp_path / 'recovery.db').as_posix()}")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
    import backend.services.detection_adapter as adapter
    original = adapter.correlate_incidents

    def fail(*args, **kwargs):
        raise RuntimeError("synthetic computation failure")

    monkeypatch.setattr(adapter, "correlate_incidents", fail)
    with SessionLocal() as db:
        status, state, result = ingest_event(db, payload(), evaluation_time=BASE)
        assert (status, state, result) == (201, "accepted", None)
    with SessionLocal() as db:
        assert db.get(LoginEvent, "same-id").detection_status == "failed"
        assert db.scalars(select(Incident)).all() == []
        assert db.scalars(select(Alert)).all() == []
    monkeypatch.setattr(adapter, "correlate_incidents", original)
    with SessionLocal() as db:
        reconcile_identity(db, "synthetic-user", evaluation_time=BASE)
        assert db.get(LoginEvent, "same-id").detection_status == "evaluated"
    engine.dispose()


def test_concurrent_bootstrap_creates_one_admin_and_one_audit(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{(tmp_path / 'bootstrap.db').as_posix()}",
                           connect_args={"check_same_thread": False, "timeout": 30})
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
    monkeypatch.setattr(manage, "SessionLocal", SessionLocal)
    monkeypatch.setattr(manage.getpass, "getpass", lambda _: "SyntheticAdminPassword123!")
    barrier = Barrier(2)

    def bootstrap(name):
        barrier.wait()
        try:
            return manage.main(["bootstrap-admin", "--username", name])
        except SystemExit:
            return "already bootstrapped"

    with ThreadPoolExecutor(max_workers=2) as workers:
        outcomes = list(workers.map(bootstrap, ["initial-one", "initial-two"]))
    assert sorted(str(value) for value in outcomes) == ["0", "already bootstrapped"]
    with SessionLocal() as db:
        assert len(db.scalars(select(User).where(User.role == "admin")).all()) == 1
        assert len(db.scalars(select(AuditLog).where(AuditLog.action == "BOOTSTRAP_ADMIN")).all()) == 1
    engine.dispose()


def test_concurrent_admin_demotions_cannot_remove_final_admin(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'demotion.db').as_posix()}",
                           connect_args={"check_same_thread": False, "timeout": 30})
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
    with SessionLocal() as db:
        names = [create_user(db, username=f"admin-{index}",
                             password="SyntheticAdminPassword123!", role="admin").id
                 for index in range(2)]
    barrier = Barrier(2)

    def demote(index):
        with SessionLocal() as db:
            current = db.get(User, names[index])
            barrier.wait()
            try:
                return update_user_role(names[index], UserRoleUpdate(role="viewer"), current, db).role
            except HTTPException as exc:
                return exc.status_code

    with ThreadPoolExecutor(max_workers=2) as workers:
        outcomes = list(workers.map(demote, [0, 1]))
    assert sorted(str(value) for value in outcomes) == ["409", "viewer"]
    with SessionLocal() as db:
        assert len(db.scalars(select(User).where(User.role == "admin")).all()) == 1
        assert len(db.scalars(select(AuditLog).where(AuditLog.action == "CHANGE_USER_ROLE")).all()) == 1
    engine.dispose()


def test_concurrent_same_identity_reconciliation_has_one_incident_and_alert(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'episode-race.db').as_posix()}",
                           connect_args={"check_same_thread": False, "timeout": 30})
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
    seed_burst(SessionLocal)
    barrier = Barrier(2)

    def submit(index):
        with SessionLocal() as db:
            barrier.wait()
            return ingest_event(db, auth_event(f"success-{index}", "LOGIN_SUCCESS", 6 + index,
                                               device=f"novel-{index}", ip=f"198.51.100.{index+2}"),
                                evaluation_time=BASE + timedelta(minutes=10))[:2]

    with ThreadPoolExecutor(max_workers=2) as workers:
        assert list(workers.map(submit, [0, 1])) == [(201, "accepted"), (201, "accepted")]
    with SessionLocal() as db:
        incidents = db.scalars(select(Incident).where(Incident.is_current.is_(True))).all()
        alerts = db.scalars(select(Alert).where(Alert.is_current.is_(True))).all()
        assert len(incidents) == len(alerts) == 1
        assert incidents[0].risk_score == 75 and incidents[0].severity == "CRITICAL"
        assert {row.event_id for row in incidents[0].events} == {
            *(f"failure-{index}" for index in range(5)), "success-0", "success-1"
        }
        assert len(incidents[0].events) == len({row.event_id for row in incidents[0].events})
    engine.dispose()


def test_concurrent_identical_success_replay_triggers_one_reconciliation(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'identical-episode.db').as_posix()}",
                           connect_args={"check_same_thread": False, "timeout": 30})
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
    seed_burst(SessionLocal)
    barrier = Barrier(2)
    success = auth_event("shared-success", "LOGIN_SUCCESS", 6,
                         device="novel", ip="198.51.100.2")

    def submit():
        with SessionLocal() as db:
            barrier.wait()
            return ingest_event(db, success, evaluation_time=BASE + timedelta(minutes=10))[:2]

    with ThreadPoolExecutor(max_workers=2) as workers:
        outcomes = list(workers.map(lambda _: submit(), range(2)))
    assert sorted(outcomes) == [(200, "duplicate"), (201, "accepted")]
    with SessionLocal() as db:
        assert len(db.scalars(select(LoginEvent).where(LoginEvent.event_id == "shared-success")).all()) == 1
        assert len(db.scalars(select(Incident)).all()) == 1
        assert len(db.scalars(select(Alert)).all()) == 1
    engine.dispose()


@pytest.mark.parametrize("failure_point", ["incident", "alert", "status"])
def test_processing_failures_roll_back_incident_alert_and_status(tmp_path, failure_point):
    engine = create_engine(f"sqlite:///{(tmp_path / f'failure-{failure_point}.db').as_posix()}")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
    seed_burst(SessionLocal)

    def fail_during_flush(session, flush_context, instances):
        if failure_point == "incident" and any(isinstance(item, Incident) for item in session.new):
            raise SQLAlchemyError("synthetic incident write failure")
        if failure_point == "alert" and any(isinstance(item, Alert) for item in session.new):
            raise SQLAlchemyError("synthetic alert write failure")
        if failure_point == "status" and any(
                isinstance(item, LoginEvent) and item.event_id == "failing-success"
                for item in session.dirty):
            raise SQLAlchemyError("synthetic status write failure")

    sa_event.listen(SessionLocal, "before_flush", fail_during_flush)
    with SessionLocal() as db:
        status, state, result = ingest_event(db, auth_event("failing-success", "LOGIN_SUCCESS", 6,
                                                           device="novel", ip="198.51.100.2"),
                                             evaluation_time=BASE + timedelta(minutes=10))
        assert (status, state, result) == (201, "accepted", None)
    sa_event.remove(SessionLocal, "before_flush", fail_during_flush)
    with SessionLocal() as db:
        assert db.get(LoginEvent, "failing-success").detection_status == (
            "pending" if failure_point == "status" else "failed"
        )
        assert db.scalars(select(Incident)).all() == []
        assert db.scalars(select(Alert)).all() == []
        reconcile_identity(db, "synthetic-user", evaluation_time=BASE + timedelta(minutes=10))
        assert db.get(LoginEvent, "failing-success").detection_status == "evaluated"
        assert len(db.scalars(select(Incident)).all()) == 1
        assert len(db.scalars(select(Alert)).all()) == 1
    engine.dispose()


def test_backdated_late_event_uses_monotonic_watermark_and_keeps_incident_id(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'watermark.db').as_posix()}")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
    seed_burst(SessionLocal)
    with SessionLocal() as db:
        ingest_event(db, auth_event("success", "LOGIN_SUCCESS", 6,
                                    device="novel", ip="198.51.100.2"),
                     evaluation_time=BASE + timedelta(minutes=10))
        stable_id = db.scalar(select(Incident.incident_id))
        assert stable_id is not None
        ingest_event(db, auth_event("watermark-eligible", "LOGIN_SUCCESS", 8,
                                    device="another", ip="198.51.100.8"),
                     evaluation_time=BASE + timedelta(minutes=5))
        assert db.get(LoginEvent, "watermark-eligible").detection_status == "evaluated"
        assert db.get(Incident, stable_id).is_current
        ingest_event(db, auth_event("future", "LOGIN_SUCCESS", 20,
                                    device="future", ip="198.51.100.20"),
                     evaluation_time=BASE + timedelta(minutes=5))
        assert db.get(LoginEvent, "future").detection_status == "pending"
        ingest_event(db, auth_event("late-failure", "LOGIN_FAILURE", -1),
                     evaluation_time=BASE + timedelta(minutes=5))
        assert db.get(Incident, stable_id).is_current
        assert db.scalar(select(Incident.incident_id)) == stable_id
        assert "late-failure" in {row.event_id for row in db.get(Incident, stable_id).events}
        reconcile_identity(db, "synthetic-user", evaluation_time=BASE + timedelta(minutes=5))
        assert db.get(LoginEvent, "future").detection_status == "pending"
        state = db.get(IdentityProcessingState, "synthetic-user")
        assert state.evaluated_through.replace(tzinfo=timezone.utc) == BASE + timedelta(minutes=10)
        reconcile_identity(db, "synthetic-user", evaluation_time=BASE + timedelta(minutes=20))
        assert db.get(LoginEvent, "future").detection_status == "evaluated"
        assert db.get(Incident, stable_id).is_current
    engine.dispose()


def test_unrelated_insert_integrity_error_is_not_treated_as_replay(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'insert-failure.db').as_posix()}")
    Base.metadata.create_all(engine)
    with engine.begin() as connection:
        connection.execute(text("CREATE TRIGGER reject_synthetic_insert BEFORE INSERT ON login_events "
                                "BEGIN SELECT RAISE(ABORT, 'synthetic insert failure'); END"))
    with sessionmaker(bind=engine)() as db:
        with pytest.raises(StorageUnavailableError):
            ingest_event(db, payload(), run_detection=False)
        assert db.get(LoginEvent, "same-id") is None
    engine.dispose()


def test_evidence_link_failure_rolls_back_without_duplicate_alert(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'evidence-failure.db').as_posix()}")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
    seed_burst(SessionLocal)
    with SessionLocal() as db:
        ingest_event(db, auth_event("first-success", "LOGIN_SUCCESS", 6,
                                    device="novel", ip="198.51.100.2"),
                     evaluation_time=BASE + timedelta(minutes=10))
        stable_id = db.scalar(select(Incident.incident_id))
        original_ids = {row.event_id for row in db.get(Incident, stable_id).events}

    def fail_evidence_flush(session, flush_context, instances):
        if any(isinstance(item, Incident) for item in session.dirty):
            raise SQLAlchemyError("synthetic evidence relationship failure")

    sa_event.listen(SessionLocal, "before_flush", fail_evidence_flush)
    with SessionLocal() as db:
        assert ingest_event(db, auth_event("second-success", "LOGIN_SUCCESS", 7,
                                           device="second", ip="198.51.100.3"),
                            evaluation_time=BASE + timedelta(minutes=10)) == (201, "accepted", None)
    sa_event.remove(SessionLocal, "before_flush", fail_evidence_flush)
    with SessionLocal() as db:
        incident = db.get(Incident, stable_id)
        assert {row.event_id for row in incident.events} == original_ids
        assert len(db.scalars(select(Incident)).all()) == 1
        assert len(db.scalars(select(Alert)).all()) == 1
        reconcile_identity(db, "synthetic-user", evaluation_time=BASE + timedelta(minutes=10))
        assert "second-success" in {row.event_id for row in db.get(Incident, stable_id).events}
        assert len(db.scalars(select(Alert)).all()) == 1
    engine.dispose()


def test_concurrent_analyst_update_and_reconciliation_keep_analyst_state(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'analyst-race.db').as_posix()}",
                           connect_args={"check_same_thread": False, "timeout": 30})
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
    seed_burst(SessionLocal)
    with SessionLocal() as db:
        ingest_event(db, auth_event("first-success", "LOGIN_SUCCESS", 6,
                                    device="novel", ip="198.51.100.2"),
                     evaluation_time=BASE + timedelta(minutes=10))
        stable_id = db.scalar(select(Incident.incident_id))
        analyst_id = create_user(db, username="synthetic-analyst",
                                 password="SyntheticPassword123!", role="analyst").id
    barrier = Barrier(2)

    def analyst_update():
        with SessionLocal() as db:
            actor = db.get(User, analyst_id)
            barrier.wait()
            return patch_incident(stable_id, IncidentUpdate(status="investigating",
                                                            description="Synthetic analyst note"), actor, db)

    def add_evidence():
        with SessionLocal() as db:
            barrier.wait()
            return ingest_event(db, auth_event("second-success", "LOGIN_SUCCESS", 7,
                                               device="second", ip="198.51.100.3"),
                                evaluation_time=BASE + timedelta(minutes=10))

    with ThreadPoolExecutor(max_workers=2) as workers:
        one = workers.submit(analyst_update)
        two = workers.submit(add_evidence)
        assert one.result().status == "investigating"
        assert two.result()[0] == 201
    with SessionLocal() as db:
        incident = db.get(Incident, stable_id)
        assert incident.status == "investigating"
        assert incident.description == "Synthetic analyst note"
        assert "second-success" in {row.event_id for row in incident.events}
        assert len(db.scalars(select(Incident)).all()) == 1
        assert len(db.scalars(select(Alert)).all()) == 1
        assert len(db.scalars(select(AuditLog).where(AuditLog.resource_id == stable_id)).all()) == 1
    engine.dispose()


def test_bootstrap_audit_failure_rolls_back_admin(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{(tmp_path / 'bootstrap-failure.db').as_posix()}")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
    monkeypatch.setattr(manage, "SessionLocal", SessionLocal)
    monkeypatch.setattr(manage.getpass, "getpass", lambda _: "SyntheticAdminPassword123!")

    def fail_audit(session, flush_context, instances):
        if any(isinstance(item, AuditLog) for item in session.new):
            raise SQLAlchemyError("synthetic audit insert failure")

    sa_event.listen(SessionLocal, "before_flush", fail_audit)
    with pytest.raises(SQLAlchemyError):
        manage.main(["bootstrap-admin", "--username", "synthetic-admin"])
    sa_event.remove(SessionLocal, "before_flush", fail_audit)
    with SessionLocal() as db:
        assert db.scalars(select(User)).all() == []
        assert db.scalars(select(AuditLog)).all() == []
    engine.dispose()


def test_response_read_failure_cannot_mark_committed_detection_failed(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{(tmp_path / 'response-read.db').as_posix()}")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
    with SessionLocal() as db:
        monkeypatch.setattr(db, "refresh", lambda *args, **kwargs: (_ for _ in ()).throw(
            SQLAlchemyError("synthetic response read failure")))
        assert ingest_event(db, payload(), evaluation_time=BASE) == (201, "accepted", None)
    with SessionLocal() as db:
        assert db.get(LoginEvent, "same-id").detection_status == "evaluated"
    engine.dispose()
