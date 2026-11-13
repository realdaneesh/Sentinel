"""Integration tests for Login Event Ingestion API conforming to API_CONTRACTS.md."""

from datetime import datetime, timezone
from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.database import Base, get_db
from backend.main import app


@pytest.fixture
def client_with_db():
    """Create a test client with an isolated in-memory SQLite database using StaticPool."""
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
        yield test_client

    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=test_engine)
    test_engine.dispose()


class TestEventIngestionContract:
    def test_post_event_201_created(self, client_with_db):
        """Test accepting a valid v1 event returns 201 Created."""
        payload = {
            "schema_version": "1.0",
            "event_id": "evt-ingest-001",
            "user_id": "student_101",
            "event_type": "LOGIN_FAILURE",
            "timestamp": "2026-11-13T10:30:00Z",
            "source": "campus-portal",
            "ip_address": "198.51.100.25",
            "device_id": "laptop-macos-1",
        }
        response = client_with_db.post("/api/v1/events", json=payload)
        assert response.status_code == 201
        data = response.json()
        assert data["schema_version"] == "1.0"
        assert data["event_id"] == "evt-ingest-001"
        assert data["status"] == "accepted"
        assert data["detection_result"] is not None
        assert data["detection_result"]["schema_version"] == "1.0"
        assert data["detection_result"]["detector_version"] == "1.0.0"

    def test_post_event_root_endpoint_compatibility(self, client_with_db):
        """Test that /events directly at root works according to docs/API_CONTRACTS.md."""
        payload = {
            "schema_version": "1.0",
            "event_id": "evt-root-001",
            "user_id": "student_102",
            "event_type": "LOGIN_SUCCESS",
            "timestamp": "2026-11-13T10:35:00Z",
            "source": "campus-portal",
        }
        response = client_with_db.post("/events", json=payload)
        assert response.status_code == 201
        assert response.json()["event_id"] == "evt-root-001"

    def test_post_event_200_duplicate_replay(self, client_with_db):
        """Test identical replay returns 200 OK with status duplicate."""
        payload = {
            "schema_version": "1.0",
            "event_id": "evt-replay-001",
            "user_id": "student_103",
            "event_type": "LOGIN_FAILURE",
            "timestamp": "2026-11-13T10:30:00Z",
            "source": "lab-portal",
        }
        res1 = client_with_db.post("/api/v1/events", json=payload)
        assert res1.status_code == 201

        # Replay with equivalent +00:00 timestamp spelling
        replay_payload = dict(payload)
        replay_payload["timestamp"] = "2026-11-13T10:30:00+00:00"

        res2 = client_with_db.post("/api/v1/events", json=replay_payload)
        assert res2.status_code == 200
        assert res2.json()["status"] == "duplicate"
        assert res2.json()["event_id"] == "evt-replay-001"

    def test_post_event_409_conflict(self, client_with_db):
        """Test existing event_id with different payload returns 409 Conflict."""
        payload1 = {
            "schema_version": "1.0",
            "event_id": "evt-conflict-001",
            "user_id": "student_104",
            "event_type": "LOGIN_FAILURE",
            "timestamp": "2026-11-13T10:30:00Z",
            "source": "lab-portal",
        }
        res1 = client_with_db.post("/api/v1/events", json=payload1)
        assert res1.status_code == 201

        payload2 = dict(payload1)
        payload2["event_type"] = "LOGIN_SUCCESS"  # Modified content

        res2 = client_with_db.post("/api/v1/events", json=payload2)
        assert res2.status_code == 409
        err = res2.json()["error"]
        assert err["code"] == "EVENT_ID_CONFLICT"
        assert err["details"][0]["field"] == "event_id"

    def test_post_event_415_unsupported_media_type(self, client_with_db):
        """Test non-JSON Content-Type returns 415."""
        response = client_with_db.post(
            "/api/v1/events",
            content="<xml></xml>",
            headers={"Content-Type": "text/xml"},
        )
        assert response.status_code == 415
        assert response.json()["error"]["code"] == "UNSUPPORTED_MEDIA_TYPE"

    def test_post_event_400_malformed_json(self, client_with_db):
        """Test malformed JSON body returns 400 INVALID_JSON."""
        response = client_with_db.post(
            "/api/v1/events",
            content="{bad_json:",
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "INVALID_JSON"

    def test_post_event_422_validation_errors(self, client_with_db):
        """Test validation rejections for missing fields, unknown fields, invalid timestamps."""
        # 1. Missing required field (event_type)
        res1 = client_with_db.post("/api/v1/events", json={
            "schema_version": "1.0",
            "event_id": "evt-val-1",
            "user_id": "user1",
            "timestamp": "2026-11-13T10:00:00Z",
            "source": "test",
        })
        assert res1.status_code == 422
        assert res1.json()["error"]["code"] == "VALIDATION_ERROR"

        # 2. Unknown field
        res2 = client_with_db.post("/api/v1/events", json={
            "schema_version": "1.0",
            "event_id": "evt-val-2",
            "user_id": "user1",
            "event_type": "LOGIN_SUCCESS",
            "timestamp": "2026-11-13T10:00:00Z",
            "source": "test",
            "extra_field": "disallowed",
        })
        assert res2.status_code == 422

        # 3. Invalid timestamp without timezone
        res3 = client_with_db.post("/api/v1/events", json={
            "schema_version": "1.0",
            "event_id": "evt-val-3",
            "user_id": "user1",
            "event_type": "LOGIN_SUCCESS",
            "timestamp": "2026-11-13 10:00:00",
            "source": "test",
        })
        assert res3.status_code == 422


class TestConvenienceLoginEndpoint:
    def test_convenience_login_ingestion(self, client_with_db):
        """Test POST /api/v1/events/login with convenience field names."""
        payload = {
            "user_id": "student_lab_202",
            "timestamp": "2026-11-13T11:00:00Z",
            "source_ip": "192.168.1.55",
            "device": "Lab Desktop",
            "application": "Physics Lab System",
            "status": "failed",
            "failure_reason": "Invalid password",
        }
        response = client_with_db.post("/api/v1/events/login", json=payload)
        assert response.status_code == 201
        data = response.json()
        assert data["status"] == "accepted"
        assert data["event_id"].startswith("evt-")


class TestEventRetrievalAndFiltering:
    def test_list_and_filter_events(self, client_with_db):
        """Test querying events with user, event_type, and pagination filters."""
        # Insert test events
        for i in range(5):
            client_with_db.post("/api/v1/events", json={
                "schema_version": "1.0",
                "event_id": f"evt-list-{i}",
                "user_id": "user_filter_a" if i < 3 else "user_filter_b",
                "event_type": "LOGIN_FAILURE" if i % 2 == 0 else "LOGIN_SUCCESS",
                "timestamp": f"2026-11-13T12:0{i}:00Z",
                "source": "web",
            })

        # Filter by user_id
        res_user = client_with_db.get("/api/v1/events?user_id=user_filter_a")
        assert res_user.status_code == 200
        data_user = res_user.json()
        assert data_user["total"] == 3
        assert len(data_user["items"]) == 3

        # Filter by event_type
        res_type = client_with_db.get("/api/v1/events?event_type=LOGIN_FAILURE")
        assert res_type.status_code == 200
        assert res_type.json()["total"] == 3

        # Test single event retrieval
        res_single = client_with_db.get("/api/v1/events/evt-list-1")
        assert res_single.status_code == 200
        assert res_single.json()["event_id"] == "evt-list-1"
        assert res_single.json()["user_id"] == "user_filter_a"

        # 404 for unknown event
        res_404 = client_with_db.get("/api/v1/events/evt-unknown")
        assert res_404.status_code == 404


class TestSimulatorEndpoint:
    def test_generate_and_ingest_synthetic_burst(self, client_with_db):
        """Test generating synthetic failed_login_burst events and storing them via API."""
        payload = {
            "scenario": "failed_login_burst",
            "seed": 100,
            "count": 5,
            "ingest": True,
        }
        response = client_with_db.post("/api/v1/simulator/generate", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["count"] == 5
        assert data["ingested"] is True

        # Verify events are stored in DB
        res_events = client_with_db.get("/api/v1/events?source=sentinel-simulator")
        assert res_events.status_code == 200
        assert res_events.json()["total"] == 5

