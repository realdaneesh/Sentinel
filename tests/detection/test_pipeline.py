"""Offline batch orchestration against the documented v1 wire contract."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import pytest

from services.detection.pipeline import evaluate_events
from services.detection.risk_scoring import score_risk
from services.simulator import generate_events


NOW = datetime(2026, 11, 4, 12, tzinfo=timezone.utc)
FIXTURES = Path(__file__).parents[1] / "fixtures" / "contracts" / "events.json"


def event(index, *, user="alice", minutes=0, kind="LOGIN_FAILURE"):
    return {
        "schema_version": "1.0", "event_id": f"evt-{index}", "user_id": user,
        "event_type": kind,
        "timestamp": (NOW + timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z"),
        "source": "test",
    }


def test_valid_contract_fixtures_and_empty_batch():
    fixtures = json.loads(FIXTURES.read_text(encoding="utf-8"))
    result = evaluate_events(fixtures["valid"], evaluation_time=NOW)
    assert [item["identity"] for item in result] == ["alice", "bob"]
    assert all(item["risk_score"] == 0 for item in result)
    assert evaluate_events([], evaluation_time=NOW) == []


@pytest.mark.parametrize("case", json.loads(FIXTURES.read_text(encoding="utf-8"))["invalid"], ids=lambda case: case["name"])
def test_invalid_contract_fixture(case):
    record = json.loads(FIXTURES.read_text(encoding="utf-8"))["valid"][0]
    record.update(case["patch"])
    for field in case.get("remove", []):
        record.pop(field)
    with pytest.raises((TypeError, ValueError)):
        evaluate_events([record], evaluation_time=NOW)


@pytest.mark.parametrize("bad", [None, "events", {"event_id": "x"}, 42])
def test_invalid_batches(bad):
    with pytest.raises(TypeError, match="events must"):
        evaluate_events(bad, evaluation_time=NOW)


@pytest.mark.parametrize("bad", [None, "2026-11-04T12:00:00Z"])
def test_invalid_evaluation_time_type(bad):
    with pytest.raises(TypeError, match="evaluation_time"):
        evaluate_events([], evaluation_time=bad)


def test_naive_evaluation_time_rejected():
    with pytest.raises(ValueError, match="timezone-aware"):
        evaluate_events([], evaluation_time=NOW.replace(tzinfo=None))


def test_bad_event_after_valid_event_rejects_whole_batch():
    with pytest.raises(TypeError, match=r"events\[1\]"):
        evaluate_events([event(0), None], evaluation_time=NOW)


def test_duplicate_idempotent_replay_and_timestamp_equivalence():
    events = [event(i, minutes=-i) for i in range(5)]
    replay = dict(events[0], timestamp=events[0]["timestamp"].replace("Z", "+00:00"))
    assert evaluate_events(events + [events[0], replay], evaluation_time=NOW) == evaluate_events(
        events, evaluation_time=NOW
    )


@pytest.mark.parametrize("patch", [
    {"user_id": "bob"}, {"source": "other"}, {"device_id": "device"},
    {"timestamp": "2026-11-04T11:59:59Z"},
])
def test_conflicting_ids_rejected(patch):
    original = event(0)
    with pytest.raises(ValueError, match="conflicting event_id"):
        evaluate_events([original, dict(original, **patch)], evaluation_time=NOW)


def test_separate_identities_and_deterministic_order_immutability():
    events = [event(i, minutes=-i) for i in range(5)]
    events += [event(i + 5, user="Bob", minutes=-i) for i in range(4)]
    original = deepcopy(events)
    result = evaluate_events(reversed(events), evaluation_time=NOW)
    assert result == evaluate_events(events, evaluation_time=NOW)
    assert events == original
    assert [item["identity"] for item in result] == ["Bob", "alice"]
    assert result[0]["failed_attempts"] == 4
    assert result[0]["triggered_signals"] == []
    assert result[1]["failed_attempts"] == 5
    assert result[1]["triggered_signals"] == ["failed_login_burst"]
    scored = score_risk(["failed_login_burst"])
    assert (result[1]["risk_score"], result[1]["severity"]) == (
        scored["risk_score"], scored["severity"]
    )
    assert result[1]["explanations"][1:] == scored["reasons"]


def test_inclusive_window_future_old_and_success_are_excluded():
    events = [event(0, minutes=-15), event(1, minutes=0), event(2, minutes=-1),
              event(3, minutes=-2), event(4, minutes=-3), event(5, minutes=-16),
              event(6, minutes=1), event(7, minutes=-4, kind="LOGIN_SUCCESS")]
    result = evaluate_events(events, evaluation_time=NOW)[0]
    assert result["failed_attempts"] == 5
    assert result["triggered_signals"] == ["failed_login_burst"]
    assert "threshold of 5 met" in result["explanations"][0]
    one_less = evaluate_events(events[1:], evaluation_time=NOW)[0]
    assert one_less["failed_attempts"] == 4
    assert one_less["risk_score"] == 0
    assert one_less["severity"] == "LOW"
    assert one_less["triggered_signals"] == []


def test_explicit_aware_offset_evaluation_time():
    offset = timezone(timedelta(hours=5, minutes=30))
    events = [event(i, minutes=-i) for i in range(5)]
    assert evaluate_events(events, evaluation_time=NOW.astimezone(offset)) == evaluate_events(
        events, evaluation_time=NOW
    )


def test_simulator_burst_and_other_scenarios():
    burst = generate_events("failed_login_burst", seed=42, reference_time=NOW)
    result = evaluate_events(burst, evaluation_time=NOW)[0]
    assert result["failed_attempts"] == 5
    assert result["risk_score"] == score_risk(["failed_login_burst"])["risk_score"]
    results = evaluate_events(
        generate_events("normal_activity", seed=42, reference_time=NOW), evaluation_time=NOW
    )
    assert all(item["triggered_signals"] == [] for item in results)
