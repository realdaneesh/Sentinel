"""Database-backed episode reconciliation using authorized synthetic telemetry."""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.database import Base, get_db
from backend.main import app
from backend import manage
from backend.models.alert import Alert
from backend.models.event import LoginEvent
from backend.models.incident import Incident
from backend.schemas.event import EventIngestPayload
from backend.services.auth_service import create_user
from backend.services.detection_adapter import _reconcile_incidents, reconcile_identity
from backend.services.event_service import ingest_event
from backend.services.producer_service import provision_producer
from services.detection.incident_correlation import correlate_incidents


BASE = datetime(2026, 11, 14, 12, tzinfo=timezone.utc)
IDENTITY = "task008c-synthetic"


@pytest.fixture
def backend_client():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)

    def override_get_db():
        with SessionLocal() as db:
            yield db

    app.dependency_overrides[get_db] = override_get_db
    with SessionLocal() as db:
        _, key = provision_producer(db, name="task008c-producer", source="task008c-producer")
        create_user(db, username="task008c-analyst", password="SyntheticPassword123!", role="analyst")
    with TestClient(app) as client:
        yield client, SessionLocal, {"X-Sentinel-Producer-Key": key}
    app.dependency_overrides.clear()
    engine.dispose()


def event(event_id, kind, minute, *, identity=IDENTITY, device=None, ip=None, timestamp=None):
    stamp = timestamp or (BASE + timedelta(minutes=minute)).isoformat().replace("+00:00", "Z")
    value = {"schema_version": "1.0", "event_id": event_id, "user_id": identity,
             "event_type": kind, "timestamp": stamp, "source": "task008c-producer"}
    if device is not None:
        value["device_id"] = device
    if ip is not None:
        value["ip_address"] = ip
    return value


def post(client, headers, value):
    response = client.post("/api/v1/events", json=value, headers=headers)
    assert response.status_code == 201, response.text
    return response


def sequence(client, headers, *, identity=IDENTITY, base_minute=-120,
             first_device="novel", first_ip="198.51.100.2"):
    records = [event(f"{identity}-baseline", "LOGIN_SUCCESS", base_minute,
                     identity=identity, device="known", ip="192.0.2.1")]
    records += [event(f"{identity}-fail-{i}", "LOGIN_FAILURE", i,
                      identity=identity) for i in range(5)]
    records += [event(f"{identity}-success-1", "LOGIN_SUCCESS", 6,
                      identity=identity, device=first_device, ip=first_ip)]
    for record in records:
        post(client, headers, record)
    return records


def _incidents(db, identity=IDENTITY):
    return list(db.scalars(select(Incident).where(Incident.user_id == identity)
                           .order_by(Incident.created_at, Incident.incident_id)).all())


def test_full_api_critical_episode_evolves_without_duplicate(backend_client):
    client, SessionLocal, headers = backend_client
    records = sequence(client, headers)
    offline = correlate_incidents(records, evaluation_time=BASE + timedelta(minutes=6))
    with SessionLocal() as db:
        first = _incidents(db)
        assert len(first) == 1
        stable_id = first[0].incident_id
        fingerprint = first[0].evidence_fingerprint
        assert fingerprint == offline[0]["incident_id"]
        assert first[0].risk_score == 75 and first[0].severity == "CRITICAL"
        assert {row.event_id for row in first[0].events} == set(offline[0]["contributing_event_ids"])
        assert db.scalar(select(Alert).where(Alert.incident_id == stable_id)) is not None
    second = event(f"{IDENTITY}-success-2", "LOGIN_SUCCESS", 7,
                   device="another", ip="198.51.100.3")
    post(client, headers, second)
    with SessionLocal() as db:
        current = _incidents(db)
        assert len(current) == 1 and current[0].incident_id == stable_id
        assert current[0].evidence_fingerprint != fingerprint
        assert len(current[0].events) == 7
        assert len({row.event_id for row in current[0].events}) == 7
        assert current[0].evidence_history[0]["fingerprint"] == fingerprint
        alert = db.scalar(select(Alert).where(Alert.incident_id == stable_id))
        assert alert.severity == "CRITICAL"
        alert_id, updated_at = alert.alert_id, current[0].updated_at
    replay = client.post("/api/v1/events", json=second, headers=headers)
    assert replay.status_code == 200 and replay.json()["status"] == "duplicate"
    equivalent = {**second, "timestamp": second["timestamp"].replace("Z", "+00:00")}
    assert client.post("/api/v1/events", json=equivalent, headers=headers).status_code == 200
    assert client.post("/api/v1/events", json=event("unauthorized-late", "LOGIN_FAILURE", 5)).status_code == 401
    with SessionLocal() as db:
        reconcile_identity(db, IDENTITY, evaluation_time=BASE + timedelta(minutes=7))
        current = _incidents(db)
        assert len(current) == 1 and current[0].updated_at == updated_at
        assert len(current[0].evidence_history) == 1
        assert db.scalar(select(Alert).where(Alert.incident_id == stable_id)).alert_id == alert_id
        assert db.get(LoginEvent, "unauthorized-late") is None
    assert client.get("/api/v1/incidents", headers=headers).status_code == 401


def test_escalation_preserves_investigation_and_acknowledgement(backend_client):
    client, SessionLocal, headers = backend_client
    sequence(client, headers, first_device="known")  # New IP only: 55/HIGH.
    with SessionLocal() as db:
        incident = _incidents(db)[0]
        stable_id = incident.incident_id
        alert_id = incident.alerts[0].alert_id
        assert incident.risk_score == 55
        incident.status = "investigating"
        incident.description = "Synthetic analyst note"
        incident.alerts[0].is_acknowledged = True
        incident.alerts[0].acknowledged_by = "task008c-analyst"
        db.commit()
    post(client, headers, event(f"{IDENTITY}-success-2", "LOGIN_SUCCESS", 7,
                                device="new-device", ip="192.0.2.1"))
    with SessionLocal() as db:
        incident = _incidents(db)[0]
        assert incident.incident_id == stable_id
        assert incident.risk_score == 75 and incident.severity == "CRITICAL"
        assert incident.status == "investigating" and incident.description == "Synthetic analyst note"
        assert len(incident.alerts) == 1
        assert incident.alerts[0].alert_id == alert_id
        assert incident.alerts[0].is_acknowledged is True
        assert incident.alerts[0].acknowledged_by == "task008c-analyst"
        assert incident.alerts[0].severity == "CRITICAL"


def test_late_failure_recomputes_prior_success_and_late_baseline_retires_incident(backend_client):
    client, SessionLocal, headers = backend_client
    post(client, headers, event("baseline", "LOGIN_SUCCESS", -120, device="known", ip="192.0.2.1"))
    for index in range(4):
        post(client, headers, event(f"failure-{index}", "LOGIN_FAILURE", index))
    response = post(client, headers, event("suspicious", "LOGIN_SUCCESS", 6,
                                           device="novel", ip="198.51.100.2"))
    assert response.json()["detection_result"]["risk_score"] == 40
    with SessionLocal() as db:
        assert _incidents(db) == []
    post(client, headers, event("failure-4", "LOGIN_FAILURE", 4))
    with SessionLocal() as db:
        assert db.get(LoginEvent, "suspicious").detection_result["risk_score"] == 75
        incident = _incidents(db)[0]
        incident.status = "investigating"
        incident.description = "Keep this analyst note"
        db.commit()
        stable_id = incident.incident_id
    # The late earlier success makes the suspicious login's identifiers familiar.
    post(client, headers, event("late-known", "LOGIN_SUCCESS", -60,
                                device="novel", ip="198.51.100.2"))
    with SessionLocal() as db:
        assert db.get(LoginEvent, "suspicious").detection_result["risk_score"] == 35
        incident = db.get(Incident, stable_id)
        assert incident.is_current is False
        assert incident.status == "investigating" and incident.description == "Keep this analyst note"
        assert incident.alerts[0].is_current is False
        alert_id = incident.alerts[0].alert_id
        assert {row.event_id for row in incident.events} == {
            "failure-0", "failure-1", "failure-2", "failure-3", "failure-4", "suspicious"
        }
    assert client.get("/api/v1/incidents?user_id=" + IDENTITY, headers=_analyst(client)).json()["total"] == 0
    assert client.get("/api/v1/incidents?user_id=" + IDENTITY + "&include_historical=true",
                      headers=_analyst(client)).json()["total"] == 1
    assert client.get("/api/v1/alerts", headers=_analyst(client)).json()["total"] == 0
    assert client.get("/api/v1/alerts?include_historical=true",
                      headers=_analyst(client)).json()["total"] == 1
    assert client.get(f"/api/v1/incidents/{stable_id}").status_code == 401
    assert client.get(f"/api/v1/alerts/{alert_id}").status_code == 401
    assert client.get(f"/api/v1/incidents/{stable_id}", headers=_analyst(client)).json()["is_current"] is False
    assert client.get(f"/api/v1/alerts/{alert_id}", headers=_analyst(client)).json()["is_current"] is False


def _analyst(client):
    response = client.post("/api/v1/auth/login", json={
        "username": "task008c-analyst", "password": "SyntheticPassword123!"})
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def test_future_event_is_pending_until_explicit_reevaluation(backend_client):
    _, SessionLocal, _ = backend_client
    before = BASE + timedelta(minutes=5)
    with SessionLocal() as db:
        baseline = event("future-baseline", "LOGIN_SUCCESS", -120,
                         device="known", ip="192.0.2.1")
        ingest_event(db, EventIngestPayload.model_validate(baseline), evaluation_time=before)
        for index in range(5):
            ingest_event(db, EventIngestPayload.model_validate(
                event(f"future-fail-{index}", "LOGIN_FAILURE", index)), evaluation_time=before)
        future = event("future-success", "LOGIN_SUCCESS", 6,
                       device="novel", ip="198.51.100.2")
        status, _, result = ingest_event(db, EventIngestPayload.model_validate(future),
                                         evaluation_time=before)
        assert status == 201 and result is None
        assert db.get(LoginEvent, "future-success").detection_status == "pending"
        assert _incidents(db) == []
        assert db.scalar(select(Alert)) is None
        reconcile_identity(db, IDENTITY, evaluation_time=BASE + timedelta(minutes=6))
        assert db.get(LoginEvent, "future-success").detection_result["risk_score"] == 75
        assert len(_incidents(db)) == 1
        assert db.scalar(select(Alert)) is not None


def test_missing_baseline_and_exact_time_boundaries(backend_client):
    client, SessionLocal, headers = backend_client
    for index in range(5):
        post(client, headers, event(f"boundary-fail-{index}", "LOGIN_FAILURE", index))
    first = post(client, headers, event("first-observed", "LOGIN_SUCCESS", 4,
                                       device="first", ip="198.51.100.2"))
    assert first.json()["detection_result"]["risk_score"] == 35
    with SessionLocal() as db:
        assert _incidents(db) == []
    # A late baseline establishes novelty, but the same-timestamp success still
    # cannot follow the burst observation at minute 4.
    post(client, headers, event("boundary-baseline", "LOGIN_SUCCESS", -120,
                                device="known", ip="192.0.2.1"))
    with SessionLocal() as db:
        assert db.get(LoginEvent, "first-observed").detection_result["risk_score"] == 75
        assert _incidents(db) == []
    # Exactly fifteen minutes after the last burst observation is included.
    post(client, headers, event("boundary-success", "LOGIN_SUCCESS", 19,
                                device="second", ip="198.51.100.3"))
    with SessionLocal() as db:
        assert len(_incidents(db)) == 1
        assert "first-observed" not in {row.event_id for row in _incidents(db)[0].events}


def test_separate_episodes_and_identities_remain_separate(backend_client):
    client, SessionLocal, headers = backend_client
    sequence(client, headers)
    sequence(client, headers, identity="other-synthetic")
    for index in range(5):
        post(client, headers, event(f"second-fail-{index}", "LOGIN_FAILURE", 60 + index))
    post(client, headers, event("second-success", "LOGIN_SUCCESS", 66,
                                device="second-device", ip="203.0.113.2"))
    with SessionLocal() as db:
        assert len(_incidents(db)) == 2
        assert len(_incidents(db, "other-synthetic")) == 1
        assert len(db.scalars(select(Alert).where(Alert.is_current.is_(True))).all()) == 3


def test_late_earlier_failure_changes_episode_start_without_changing_persistent_id(backend_client):
    client, SessionLocal, headers = backend_client
    sequence(client, headers)
    with SessionLocal() as db:
        original = _incidents(db)[0]
        stable_id = original.incident_id
        first_start = original.start_time
        fingerprint = original.evidence_fingerprint
    post(client, headers, event("earlier-failure", "LOGIN_FAILURE", -1))
    with SessionLocal() as db:
        incidents = _incidents(db)
        assert len(incidents) == 1 and incidents[0].incident_id == stable_id
        assert incidents[0].start_time < first_start
        assert incidents[0].evidence_fingerprint != fingerprint
        assert "earlier-failure" in {row.event_id for row in incidents[0].events}
        assert len(incidents[0].alerts) == 1


def test_merge_preserves_historical_investigation(backend_client):
    client, SessionLocal, headers = backend_client
    post(client, headers, event("merge-baseline", "LOGIN_SUCCESS", -120,
                                device="known", ip="192.0.2.1"))
    for minute in range(5):
        post(client, headers, event(f"merge-a-{minute}", "LOGIN_FAILURE", minute))
    post(client, headers, event("merge-success-a", "LOGIN_SUCCESS", 6,
                                device="new-a", ip="198.51.100.2"))
    for minute in range(20, 25):
        post(client, headers, event(f"merge-b-{minute}", "LOGIN_FAILURE", minute))
    post(client, headers, event("merge-success-b", "LOGIN_SUCCESS", 26,
                                device="new-b", ip="198.51.100.3"))
    with SessionLocal() as db:
        initial = _incidents(db)
        assert len(initial) == 2
        for incident in initial:
            incident.status = "investigating"
            incident.description = f"Analyst note for {incident.incident_id}"
        db.commit()
    for minute in (10, 12, 14, 16, 18):
        post(client, headers, event(f"merge-bridge-{minute}", "LOGIN_FAILURE", minute))
    with SessionLocal() as db:
        incidents = _incidents(db)
        assert len(incidents) == 2
        current = [item for item in incidents if item.is_current]
        historical = [item for item in incidents if not item.is_current]
        assert len(current) == len(historical) == 1
        assert current[0].status == historical[0].status == "investigating"
        assert historical[0].superseded_by_id == current[0].incident_id
        assert historical[0].description.startswith("Analyst note")
        assert all(not alert.is_current for alert in historical[0].alerts)
        assert len(db.scalars(select(Alert).where(Alert.is_current.is_(True))).all()) == 1


def test_split_matching_keeps_strongest_overlap_and_lineage(backend_client):
    _, SessionLocal, _ = backend_client
    with SessionLocal() as db:
        events = []
        for index in range(7):
            row = LoginEvent(event_id=f"split-{index}", user_id=IDENTITY,
                             event_type="LOGIN_FAILURE", timestamp=BASE + timedelta(minutes=index),
                             source="task008c-producer", payload_hash=f"hash-{index}")
            db.add(row)
            events.append(row)
        old = Incident(incident_id="inc-stable-split", user_id=IDENTITY,
                       incident_type="failed_login_burst_followed_by_unfamiliar_login",
                       title="Prior episode", description="Analyst note", status="investigating",
                       risk_score=75, severity="CRITICAL", start_time=BASE,
                       end_time=BASE + timedelta(minutes=6), signals=["failed_login_burst"],
                       explanations=["prior"], evidence_fingerprint="old-fingerprint")
        old.events = events
        db.add(old)
        db.commit()
        def result(fingerprint, ids):
            return {"incident_id": fingerprint, "identity": IDENTITY,
                    "incident_type": old.incident_type, "contributing_event_ids": ids,
                    "start_time": BASE.isoformat().replace("+00:00", "Z"),
                    "end_time": (BASE + timedelta(minutes=6)).isoformat().replace("+00:00", "Z"),
                    "risk_score": 75, "severity": "CRITICAL", "signals": ["failed_login_burst"],
                    "explanations": [fingerprint], "scorer_version": "1.0.0"}
        _reconcile_incidents(db, IDENTITY, [result("new-a", [f"split-{i}" for i in range(4)]),
                                            result("new-b", [f"split-{i}" for i in range(4, 7)])], events)
        db.commit()
        incidents = _incidents(db)
        assert len(incidents) == 2
        survivor = db.get(Incident, "inc-stable-split")
        assert survivor.is_current and survivor.status == "investigating"
        assert {row.event_id for row in survivor.events} == {f"split-{i}" for i in range(4)}
        child = next(item for item in incidents if item.incident_id != survivor.incident_id)
        assert child.split_from_id == survivor.incident_id and child.status == "open"


def test_equal_overlap_tie_and_overlapping_ranges_do_not_reuse_old_episode(backend_client):
    _, SessionLocal, _ = backend_client
    with SessionLocal() as db:
        events = []
        for index in range(6):
            row = LoginEvent(event_id=f"tie-{index}", user_id=IDENTITY,
                             event_type="LOGIN_FAILURE", timestamp=BASE + timedelta(minutes=index),
                             source="task008c-producer", payload_hash=f"tie-hash-{index}")
            db.add(row)
            events.append(row)
        old = Incident(incident_id="inc-tie-stable", user_id=IDENTITY,
                       incident_type="failed_login_burst_followed_by_unfamiliar_login",
                       title="Prior episode", description="Analyst description", status="investigating",
                       risk_score=75, severity="CRITICAL", start_time=BASE,
                       end_time=BASE + timedelta(minutes=5), signals=["failed_login_burst"],
                       explanations=["prior"], evidence_fingerprint="prior")
        old.events = events[:4]
        db.add(old)
        db.commit()

        def result(fingerprint, ids):
            return {"incident_id": fingerprint, "identity": IDENTITY,
                    "incident_type": old.incident_type, "contributing_event_ids": ids,
                    "start_time": BASE.isoformat().replace("+00:00", "Z"),
                    "end_time": (BASE + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
                    "risk_score": 75, "severity": "CRITICAL", "signals": ["failed_login_burst"],
                    "explanations": [fingerprint], "scorer_version": "1.0.0"}

        # Both children overlap the old evidence equally. The fingerprint breaks
        # the tie, independent of result order; identical time ranges do not match.
        _reconcile_incidents(db, IDENTITY, [result("z-child", ["tie-2", "tie-3"]),
                                            result("a-child", ["tie-0", "tie-1"]),
                                            result("unrelated", ["tie-4", "tie-5"])], events)
        db.commit()
        incidents = _incidents(db)
        assert len(incidents) == 3
        survivor = db.get(Incident, "inc-tie-stable")
        assert survivor.evidence_fingerprint == "a-child"
        assert survivor.description == "Analyst description" and survivor.status == "investigating"
        children = [item for item in incidents if item.incident_id != survivor.incident_id]
        assert {item.evidence_fingerprint for item in children} == {"z-child", "unrelated"}
        assert next(item for item in children if item.evidence_fingerprint == "z-child").split_from_id == survivor.incident_id
        assert next(item for item in children if item.evidence_fingerprint == "unrelated").split_from_id is None
        before = {item.incident_id: (item.updated_at, list(item.evidence_history)) for item in incidents}
        _reconcile_incidents(db, IDENTITY, [result("z-child", ["tie-2", "tie-3"]),
                                            result("a-child", ["tie-0", "tie-1"]),
                                            result("unrelated", ["tie-4", "tie-5"])], events)
        db.commit()
        assert {item.incident_id: (item.updated_at, list(item.evidence_history)) for item in _incidents(db)} == before
        _reconcile_incidents(db, IDENTITY, [], events)
        db.commit()
        assert all(not item.is_current for item in _incidents(db))
        _reconcile_incidents(db, IDENTITY, [result("a-child", ["tie-0", "tie-1"])], events)
        db.commit()
        current = [item for item in _incidents(db) if item.is_current]
        assert len(current) == 1 and current[0].incident_id != survivor.incident_id
        assert {row.event_id for row in db.get(Incident, survivor.incident_id).events} == {
            "tie-0", "tie-1"
        }
        assert db.get(Incident, survivor.incident_id).status == "investigating"


def test_reevaluate_due_orders_identities_and_leaves_future_events_pending(backend_client, monkeypatch):
    _, SessionLocal, _ = backend_client
    with SessionLocal() as db:
        for identity, event_id, minute in (("z-synthetic", "z-due", 0),
                                           ("a-synthetic", "a-due", 0),
                                           ("a-synthetic", "a-future", 10)):
            db.add(LoginEvent(event_id=event_id, user_id=identity,
                              event_type="LOGIN_SUCCESS", timestamp=BASE + timedelta(minutes=minute),
                              source="task008c-producer", payload_hash=f"hash-{event_id}",
                              detection_status="pending"))
        db.commit()
    monkeypatch.setattr(manage, "SessionLocal", SessionLocal)
    monkeypatch.setattr(manage, "init_db", lambda: None)
    visited = []
    actual_reconcile = manage.reconcile_identity

    def recording_reconcile(db, identity, *, evaluation_time):
        visited.append(identity)
        return actual_reconcile(db, identity, evaluation_time=evaluation_time)

    monkeypatch.setattr(manage, "reconcile_identity", recording_reconcile)
    assert manage.main(["reevaluate-due", "--at", (BASE + timedelta(minutes=5)).isoformat()]) == 0
    assert visited == ["a-synthetic", "z-synthetic"]
    with SessionLocal() as db:
        assert db.get(LoginEvent, "a-due").detection_status == "evaluated"
        assert db.get(LoginEvent, "z-due").detection_status == "evaluated"
        assert db.get(LoginEvent, "a-future").detection_status == "pending"
        assert db.get(LoginEvent, "a-future").detection_result is None
    assert manage.main(["reevaluate-due", "--at", (BASE + timedelta(minutes=10)).isoformat(),
                        "--identity", "a-synthetic"]) == 0
    assert visited[-1] == "a-synthetic"
    with SessionLocal() as db:
        assert db.get(LoginEvent, "a-future").detection_status == "evaluated"
    with pytest.raises(SystemExit):
        manage.main(["reevaluate-due", "--at", (BASE + timedelta(minutes=5)).isoformat(),
                     "--identity", "a-synthetic"])
    monkeypatch.setattr(manage, "_utc_now", lambda: BASE + timedelta(minutes=12))
    with pytest.raises(SystemExit):
        manage.main(["reevaluate-due", "--at", (BASE + timedelta(minutes=20)).isoformat(),
                     "--identity", "a-synthetic"])
    with SessionLocal() as db:
        assert db.get(LoginEvent, "a-future").detection_status == "evaluated"
